use std::io::Write;

use anyhow::{Context, Result, anyhow, ensure};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};

type Cipher = XChaCha20Poly1305;

pub const MAGIC: &[u8; 8] = b"LUAUBYTX";
pub const LUAUCX_VERSION: u8 = 1;
pub const AEAD_XCHACHA20: u8 = 1;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

pub const HEADER_LEN: usize = MAGIC.len()
    + (2 * size_of::<u8>())
    + size_of::<u16>()
    + (2 * size_of::<u32>())
    + NONCE_LEN
    + TAG_LEN;

fn read_bytes<'a>(input: &'a [u8], off: &mut usize, len: usize) -> &'a [u8] {
    let start = *off;
    *off += len;
    &input[start..*off]
}

fn read_u8(input: &[u8], off: &mut usize) -> u8 {
    let v = input[*off];
    *off += 1;
    v
}

fn read_u16(input: &[u8], off: &mut usize) -> u16 {
    let start = *off;
    *off += 2;
    u16::from_le_bytes(input[start..*off].try_into().unwrap())
}

fn read_u32(input: &[u8], off: &mut usize) -> u32 {
    let start = *off;
    *off += 4;
    u32::from_le_bytes(input[start..*off].try_into().unwrap())
}

fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0; NONCE_LEN];
    rand::fill(&mut nonce);
    nonce
}

pub fn encrypt_bytecode_into(
    bytecode: &[u8],
    nonce: Option<[u8; NONCE_LEN]>,
    key: &[u8],
    key_id: u16,
    ad: &[u8],
    out_buf: &mut dyn Write,
) -> Result<usize> {
    ensure!(key.len() == 32, "key must be 32 bytes");

    let nonce = &nonce.unwrap_or_else(random_nonce);

    let cipher = Cipher::new(key.into());
    let ciphertext = cipher
        .encrypt(
            nonce.into(),
            Payload {
                msg: bytecode,
                aad: ad,
            },
        )
        .map_err(|e| anyhow!(e))
        .context("encryption failed")?;
    let ct_len = ciphertext.len() - TAG_LEN;
    let (ct, tag) = ciphertext.split_at(ct_len);

    out_buf.write_all(MAGIC)?;
    out_buf.write_all(&[LUAUCX_VERSION, AEAD_XCHACHA20])?;
    out_buf.write_all(key_id.to_le_bytes().as_ref())?;
    out_buf.write_all((ad.len() as u32).to_le_bytes().as_ref())?;
    out_buf.write_all((ct.len() as u32).to_le_bytes().as_ref())?;

    out_buf.write_all(nonce)?;
    out_buf.write_all(tag)?;
    out_buf.write_all(ct)?;
    out_buf.write_all(ad)?;

    Ok(HEADER_LEN + ct.len() + ad.len())
}

pub fn decrypt_bytecode_into(
    blob: &[u8],
    key: &[u8],
    expected_key_id: Option<u16>,
    out_buf: &mut dyn Write,
    ad_buf: Option<&mut dyn Write>,
) -> Result<(usize, Option<usize>)> {
    ensure!(key.len() == 32, "key must be 32 bytes");

    let mut off = 0;

    let magic = read_bytes(blob, &mut off, MAGIC.len());
    ensure!(magic == MAGIC, "invalid bytecode");

    let ver = read_u8(blob, &mut off);
    ensure!(ver == LUAUCX_VERSION, "unsupported version {}", ver);

    let aead_id = read_u8(blob, &mut off);
    ensure!(aead_id == AEAD_XCHACHA20, "unsupported aead id {}", aead_id);

    let key_id = read_u16(blob, &mut off);
    if let Some(expected) = expected_key_id {
        ensure!(
            expected == key_id,
            "key ID mismatch (expected {}, got {})",
            expected,
            key_id
        );
    }

    let ad_len = read_u32(blob, &mut off) as usize;
    let ct_len = read_u32(blob, &mut off) as usize;

    let nonce: &[u8; NONCE_LEN] = read_bytes(blob, &mut off, NONCE_LEN).try_into().unwrap();
    let tag: &[u8; TAG_LEN] = read_bytes(blob, &mut off, TAG_LEN).try_into().unwrap();
    let ct = read_bytes(blob, &mut off, ct_len);
    let ad = read_bytes(blob, &mut off, ad_len);

    // println!("ad: {:?}", ad);
    // println!("nonce: {:?}", nonce);
    // println!("ct: {:?}", ct);
    // println!("tag: {:?}", tag);

    let mut ct_and_tag = Vec::with_capacity(ct_len + TAG_LEN);
    ct_and_tag.extend_from_slice(ct);
    ct_and_tag.extend_from_slice(tag);

    let cipher = Cipher::new(key.into());

    let pt = cipher
        .decrypt(
            nonce.into(),
            Payload {
                msg: &ct_and_tag,
                aad: ad,
            },
        )
        .map_err(|e| anyhow!(e))
        .context("decryption failed")?;

    let mut ad_written = None;
    if let Some(buf) = ad_buf {
        buf.write_all(ad)
            .context("failed to write additional data")?;
        ad_written = Some(ad.len())
    }

    out_buf
        .write_all(&pt)
        .context("failed to write plaintext")?;
    Ok((pt.len(), ad_written))
}
