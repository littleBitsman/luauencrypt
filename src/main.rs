use clap::{CommandFactory, Parser, error::ErrorKind as ClapErrorKind};
use std::{
    env::current_dir,
    ffi::OsString,
    fmt,
    fs::{self, File},
    path::PathBuf,
};

mod compile;
pub use compile::{lua_CompileOptions, luau_compile};

mod luaucx;
pub use luaucx::*;

mod cli;
use cli::*;

fn encrypt(
    data: Vec<(PathBuf, Vec<u8>)>,
    out_dir: PathBuf,
    key: &[u8],
    key_id: Option<u16>,
    aad: &[u8],
) {
    for (path, bytecode) in data {
        // SAFETY: file_name will exist since it refers to a file path (perf boost?)
        let out_path =
            unsafe { out_dir.join(path.with_extension("luaucx").file_name().unwrap_unchecked()) };
        let mut out_file = File::create(&out_path).expect("failed to create output file");
        encrypt_bytecode_into(
            &bytecode,
            None,
            key,
            key_id.unwrap_or(0),
            aad,
            &mut out_file,
        )
        .unwrap_or_else(|e| {
            err(
                format!("failed to encrypt {}: {}", path.display(), e),
                ClapErrorKind::Io,
            )
        });
        out_file.sync_all().unwrap_or_else(|e| {
            err(
                format!("failed to write {}: {}", out_path.display(), e),
                ClapErrorKind::Io,
            )
        });
        println!(
            "Successfully encrypted {} to {}",
            path.display(),
            out_path.display()
        );
    }
}

fn err(msg: impl fmt::Display, kind: ClapErrorKind) -> ! {
    Args::command().error(kind, msg).exit()
}

fn main() {
    let args = Args::parse();

    let key = fs::read(&args.key).expect("failed to read key file");
    if key.len() != 32 {
        err(
            "key file must be exactly 32 bytes",
            ClapErrorKind::InvalidValue,
        );
    }
    let out_dir = args.out_dir.unwrap_or_else(|| current_dir().unwrap());
    fs::create_dir_all(&out_dir).unwrap_or_else(|e| {
        err(
            format!("failed to create output directory: {}", e),
            ClapErrorKind::Io,
        )
    });

    match args.command {
        Subcommands::Compile {
            opt_lvl,
            debug_lvl,
            aad,
            input,
        } => {
            let opts = lua_CompileOptions {
                debugLevel: debug_lvl as i32,
                optimizationLevel: opt_lvl as i32,
                ..Default::default()
            };

            let mut compiled = Vec::with_capacity(input.len());
            for path in input {
                let source = fs::read(&path).unwrap_or_else(|e| {
                    err(
                        format!("failed to read {}: {}", path.display(), e),
                        ClapErrorKind::Io,
                    )
                });
                let bytecode = unsafe { luau_compile(&source, opts) };
                compiled.push((path.clone(), bytecode));
                println!("Successfully compiled {}", path.display());
            }
            let aad = aad.unwrap_or_else(OsString::new);
            let aad = aad.as_encoded_bytes();
            encrypt(compiled, out_dir, &key, args.key_id, aad);
        }
        Subcommands::Encrypt { aad, input } => {
            let aad = aad.unwrap_or_else(OsString::new);
            let aad = aad.as_encoded_bytes();
            let compiled = input
                .into_iter()
                .map(|path| {
                    let bytecode = fs::read(&path).expect("failed to read input file");
                    (path, bytecode)
                })
                .collect();
            encrypt(compiled, out_dir, &key, args.key_id, aad);
        }
        Subcommands::Decrypt { input } => {
            for path in input {
                let bytecode = fs::read(&path).expect("failed to read input file");
                // SAFETY: file_name will exist since it refers to a file path (perf boost?)
                let out_path = unsafe {
                    out_dir.join(path.with_extension("luauc").file_name().unwrap_unchecked())
                };
                let mut out_file = File::create(&out_path).expect("failed to create output file");
                let (_pt_len, _ad_len) =
                    decrypt_bytecode_into(&bytecode, &key, args.key_id, &mut out_file, None)
                        .expect("failed to decrypt bytecode");
                out_file.sync_all().unwrap_or_else(|e| {
                    err(
                        format!("failed to write {}: {}", out_path.display(), e),
                        ClapErrorKind::Io,
                    )
                });
                println!(
                    "Successfully decrypted {} to {}",
                    path.display(),
                    out_path.display()
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    macro_rules! bench {
        { $($tt:tt)* } => {{
            let start = Instant::now();
            let result = { $($tt)* };
            let duration = start.elapsed();
            (duration, result)
        }};
    }

    macro_rules! impl_print_trait {
        {
            $($n:ident = {
                trait = $t:path,
                fmt = $fmt:tt
            }),*
        } => {
            $(
                struct $n<T: $t>(T);
                impl<T: $t> ::std::ops::Drop for $n<T> {
                    fn drop(&mut self) {
                        println!($fmt, self.0);
                    }
                }
                impl<T: $t> ::std::ops::Deref for $n<T> {
                    type Target = T;
                    fn deref(&self) -> &Self::Target {
                        &self.0
                    }
                }
                impl<T: $t> ::std::ops::DerefMut for $n<T> {
                    fn deref_mut(&mut self) -> &mut Self::Target {
                        &mut self.0
                    }
                }
            )*
        };
    }

    impl_print_trait! {
        DebugOnDrop = {
            trait = fmt::Debug,
            fmt = "{:?}"
        },
        DisplayOnDrop = {
            trait = fmt::Display,
            fmt = "{}"
        }
    }

    #[test]
    fn compile() -> anyhow::Result<()> {
        let source = fs::read("example.luau")?;
        let opts = DisplayOnDrop(lua_CompileOptions::default());
        let (comp_dur, bytecode) = bench! {
            unsafe { luau_compile(&source, *opts) }
        };
        println!("compilation took {:?}", comp_dur);

        let mut key = DebugOnDrop([0; 32]);
        rand::fill(&mut *key);

        let mut encrypted = Vec::with_capacity(bytecode.len() + HEADER_LEN);
        let (enc_dur, _written_bytes) = bench! {
            encrypt_bytecode_into(&bytecode, None, &*key, 0, &[], &mut encrypted)?
        };
        println!("encryption took {:?}", enc_dur);

        let mut decrypted = Vec::with_capacity(bytecode.len());
        let (dec_dur, (_read_bytes, _ad_size)) = bench! {
            decrypt_bytecode_into(&encrypted, &*key, Some(0), &mut decrypted, None)?
        };
        assert_eq!(bytecode, decrypted);
        println!("decryption took {:?}", dec_dur);

        Ok(())
    }
}
