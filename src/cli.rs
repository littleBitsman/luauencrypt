use clap::{Parser, Subcommand, ValueEnum};
use std::{ffi::OsString, path::PathBuf};

#[derive(Clone, Copy, ValueEnum, Debug)]
pub enum Target {
    #[value(name = "a64")]
    A64,

    #[value(name = "x64")]
    X64,

    #[value(name = "a64_nf")]
    A64NF,

    #[value(name = "x64_ms")]
    X64MS
}

#[derive(Clone, Copy, ValueEnum, Debug)]
pub enum Mode {
    #[value(name = "encrypt")]
    Encrypt,

    #[value(name = "decrypt")]
    Decrypt
}

#[derive(Subcommand, Debug)]
pub enum Subcommands {
    /// compiles & encrypts Luau source files
    Compile {
        #[arg(
            short = 'O', 
            num_args(0..=1),
            default_value_t = 1,
            value_parser = clap::value_parser!(u8).range(0..=2)
        )]
        /// compile with optimization level n (n should be between 0 and 2)
        opt_lvl: u8,

        #[arg(
            short = 'g', 
            num_args(0..=1), 
            default_value_t = 1,
            value_parser = clap::value_parser!(u8).range(0..=2)
        )]
        /// compile with debug level n (n should be between 0 and 2)
        debug_lvl: u8,

        #[arg(
            long,
            num_args(1)
        )]
        /// optional additional data to encode
        aad: Option<OsString>,

        #[arg(num_args(1..))]
        /// Input Luau file(s) to compile & encrypt
        input: Vec<PathBuf>,
    },

    /// encrypts Luau bytecode files
    Encrypt {
        #[arg(
            long,
            num_args(1)
        )]
        /// optional additional data to encode
        aad: Option<OsString>,

        #[arg(num_args(1..))]
        /// Input Luau bytecode file(s) to encrypt
        input: Vec<PathBuf>,
    },

    /// decrypts Luau encrypted bytecode files
    Decrypt {
        #[arg(num_args(1..))]
        /// Input Luau encrypted bytecode file(s) to decrypt
        input: Vec<PathBuf>,
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, arg_required_else_help(true))]
pub struct Args {
    #[command(subcommand)]
    pub command: Subcommands,

    #[arg(
        short,
        long,
        num_args(1)
    )]
    /// path to encryption key file
    pub key: PathBuf,

    #[arg(
        long
    )]
    /// key ID to use in the file header, expected to match if decrypting
    pub key_id: Option<u16>,

    #[arg(
        long,
        num_args(1)
    )]
    /// directory to output files in, defaults to working directory
    pub out_dir: Option<PathBuf>,
}