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
    ensure!(ver == LUAUCX_VERSION, "unsupported version {ver}");

    let aead_id = read_u8(blob, &mut off);
    ensure!(aead_id == AEAD_XCHACHA20, "unsupported aead id {aead_id}");

    let key_id = read_u16(blob, &mut off);
    if let Some(expected) = expected_key_id {
        ensure!(
            expected == key_id,
            "key ID mismatch (expected {expected}, got {key_id})"
        );
    }

    let ad_len = read_u32(blob, &mut off) as usize;
    let ct_len = read_u32(blob, &mut off) as usize;

    #[expect(clippy::missing_panics_doc)]
    let (nonce, tag): (&[u8; NONCE_LEN], &[u8; TAG_LEN]) = (
        read_bytes(blob, &mut off, NONCE_LEN).try_into().unwrap(),
        read_bytes(blob, &mut off, TAG_LEN).try_into().unwrap(),
    );
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
        ad_written = Some(ad.len());
    }

    out_buf
        .write_all(&pt)
        .context("failed to write plaintext")?;
    Ok((pt.len(), ad_written))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rand_bytes<const N: usize>() -> [u8; N] {
        let mut b = [0; N];
        rand::fill(&mut b);
        b
    }

    fn test_key() -> [u8; 32] {
        rand_bytes()
    }

    fn test_nonce() -> [u8; NONCE_LEN] {
        rand_bytes()
    }

    #[test]
    fn test_read_bytes_single() {
        let data = b"hello world";
        let mut off = 0;
        let result = read_bytes(data, &mut off, 5);
        assert_eq!(result, b"hello");
        assert_eq!(off, 5);
    }

    #[test]
    fn test_read_bytes_sequential() {
        let data = b"hello world";
        let mut off = 0;
        let first = read_bytes(data, &mut off, 5);
        let second = read_bytes(data, &mut off, 6);
        assert_eq!(first, b"hello");
        assert_eq!(second, b" world");
        assert_eq!(off, 11);
    }

    #[test]
    fn test_read_u8() {
        let data = [42u8, 100, 255];
        let mut off = 0;
        let v1 = read_u8(&data, &mut off);
        assert_eq!(v1, 42);
        assert_eq!(off, 1);
        let v2 = read_u8(&data, &mut off);
        assert_eq!(v2, 100);
        assert_eq!(off, 2);
    }

    #[test]
    fn test_read_u16_little_endian() {
        let data = [0x34u8, 0x12, 0xFF, 0xFF];
        let mut off = 0;
        let v = read_u16(&data, &mut off);
        assert_eq!(v, 0x1234); // little-endian
        assert_eq!(off, 2);
    }

    #[test]
    fn test_read_u32_little_endian() {
        let data = [0x78u8, 0x56, 0x34, 0x12, 0xFF];
        let mut off = 0;
        let v = read_u32(&data, &mut off);
        assert_eq!(v, 0x12345678); // little-endian
        assert_eq!(off, 4);
    }

    #[test]
    fn test_read_mixed_sequential() {
        let mut data = Vec::new();
        data.extend_from_slice(b"HEADER");
        data.push(5);
        data.extend_from_slice(&0x1234u16.to_le_bytes());
        data.extend_from_slice(&0x12345678u32.to_le_bytes());

        let mut off = 0;
        let header = read_bytes(&data, &mut off, 6);
        let byte = read_u8(&data, &mut off);
        let short = read_u16(&data, &mut off);
        let long = read_u32(&data, &mut off);

        assert_eq!(header, b"HEADER");
        assert_eq!(byte, 5);
        assert_eq!(short, 0x1234);
        assert_eq!(long, 0x12345678);
    }

    #[test]
    fn test_encrypt_with_invalid_key_length() {
        let bytecode = b"test bytecode";
        let key = [0u8; 16]; // wrong length
        let mut out = Vec::new();

        let result = encrypt_bytecode_into(
            bytecode,
            Some(test_nonce()),
            &key,
            0,
            b"",
            &mut out,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("32 bytes"));
    }

    #[test]
    fn test_encrypt_empty_bytecode() {
        let bytecode = b"";
        let key = test_key();
        let nonce = test_nonce();
        let mut out = Vec::new();

        let result = encrypt_bytecode_into(bytecode, Some(nonce), &key, 42, b"aad", &mut out);
        assert!(result.is_ok());

        let size = result.unwrap();
        assert!(size > HEADER_LEN); // at least header + tag
        assert!(!out.is_empty());

        // Verify magic
        assert_eq!(&out[..MAGIC.len()], MAGIC);
    }

    #[test]
    fn test_encrypt_with_additional_data() {
        let bytecode = b"test bytecode";
        let aad = b"additional authenticated data";
        let key = test_key();
        let nonce = test_nonce();
        let mut out = Vec::new();

        let result = encrypt_bytecode_into(bytecode, Some(nonce), &key, 123, aad, &mut out);
        assert!(result.is_ok());

        let size = result.unwrap();
        assert_eq!(size, out.len());
        // Size should be: header + ciphertext + aad
        assert!(size > HEADER_LEN + bytecode.len());
    }

    #[test]
    fn test_decrypt_invalid_magic() {
        let mut blob = vec![0u8; 100];
        blob[0..8].copy_from_slice(b"BADMAGIC");

        let key = test_key();
        let mut out = Vec::new();

        let result = decrypt_bytecode_into(&blob, &key, None, &mut out, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid bytecode"));
    }

    #[test]
    fn test_decrypt_invalid_version() {
        let mut blob = vec![0u8; 100];
        blob[0..8].copy_from_slice(MAGIC);
        blob[8] = 99; // invalid version

        let key = test_key();
        let mut out = Vec::new();

        let result = decrypt_bytecode_into(&blob, &key, None, &mut out, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported version"));
    }

    #[test]
    fn test_decrypt_invalid_aead_id() {
        let mut blob = vec![0u8; 100];
        blob[0..8].copy_from_slice(MAGIC);
        blob[8] = LUAUCX_VERSION;
        blob[9] = 99; // invalid aead id

        let key = test_key();
        let mut out = Vec::new();

        let result = decrypt_bytecode_into(&blob, &key, None, &mut out, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported aead id"));
    }

    #[test]
    fn test_key_id_validation() {
        let bytecode = b"test";
        let key = test_key();
        let nonce = test_nonce();
        let mut encrypted = Vec::new();

        // Encrypt with key_id = 42
        encrypt_bytecode_into(bytecode, Some(nonce), &key, 42, b"", &mut encrypted)
            .expect("encryption failed");

        let mut decrypted = Vec::new();

        // Decrypt with correct key_id
        let result = decrypt_bytecode_into(&encrypted, &key, Some(42), &mut decrypted, None);
        assert!(result.is_ok());

        // Decrypt with wrong key_id
        let mut decrypted_wrong = Vec::new();
        let result = decrypt_bytecode_into(&encrypted, &key, Some(99), &mut decrypted_wrong, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("key ID mismatch"));
    }

    #[test]
    fn test_round_trip_encryption_decryption() {
        let original_bytecode = b"print('Hello, world!')";
        let key = test_key();
        let nonce = test_nonce();
        let aad = b"metadata";

        // Encrypt
        let mut encrypted = Vec::new();
        encrypt_bytecode_into(original_bytecode, Some(nonce), &key, 1, aad, &mut encrypted)
            .expect("encryption failed");

        // Decrypt
        let mut decrypted_bytecode = Vec::new();
        let mut decrypted_aad = Vec::new();
        let (bytecode_len, aad_len) = decrypt_bytecode_into(
            &encrypted,
            &key,
            Some(1),
            &mut decrypted_bytecode,
            Some(&mut decrypted_aad),
        )
        .expect("decryption failed");

        assert_eq!(decrypted_bytecode, original_bytecode);
        assert_eq!(decrypted_aad, aad);
        assert_eq!(bytecode_len, original_bytecode.len());
        assert_eq!(aad_len, Some(aad.len()));
    }

    #[test]
    fn test_round_trip_no_aad() {
        let original_bytecode = b"local x = 42";
        let key = test_key();
        let nonce = test_nonce();

        let mut encrypted = Vec::new();
        encrypt_bytecode_into(original_bytecode, Some(nonce), &key, 0, b"", &mut encrypted)
            .expect("encryption failed");

        let mut decrypted = Vec::new();
        let (len, aad_len) =
            decrypt_bytecode_into(&encrypted, &key, None, &mut decrypted, None)
                .expect("decryption failed");

        assert_eq!(decrypted, original_bytecode);
        assert_eq!(len, original_bytecode.len());
        assert_eq!(aad_len, None);
    }

    #[test]
    fn test_round_trip_large_bytecode() {
        let original_bytecode = vec![42u8; 10000];
        let key = test_key();
        let nonce = test_nonce();
        let aad = b"large file";

        let mut encrypted = Vec::new();
        encrypt_bytecode_into(&original_bytecode, Some(nonce), &key, 255, aad, &mut encrypted)
            .expect("encryption failed");

        let mut decrypted = Vec::new();
        let mut decrypted_aad = Vec::new();
        decrypt_bytecode_into(
            &encrypted,
            &key,
            Some(255),
            &mut decrypted,
            Some(&mut decrypted_aad),
        )
        .expect("decryption failed");

        assert_eq!(decrypted, original_bytecode);
        assert_eq!(decrypted_aad, aad);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let bytecode = b"secret message";
        let key = test_key();
        let wrong_key = [99u8; 32];
        let nonce = test_nonce();

        let mut encrypted = Vec::new();
        encrypt_bytecode_into(bytecode, Some(nonce), &key, 0, b"", &mut encrypted)
            .expect("encryption failed");

        let mut decrypted = Vec::new();
        let result = decrypt_bytecode_into(&encrypted, &wrong_key, None, &mut decrypted, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("decryption failed"));
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let bytecode = b"test data";
        let key = test_key();
        let nonce = test_nonce();

        let mut encrypted = Vec::new();
        encrypt_bytecode_into(bytecode, Some(nonce), &key, 0, b"", &mut encrypted)
            .expect("encryption failed");

        // Corrupt a byte in the ciphertext (after the tag)
        if encrypted.len() > HEADER_LEN + TAG_LEN {
            encrypted[HEADER_LEN + TAG_LEN] ^= 0xFF;
            let mut decrypted = Vec::new();
            let result = decrypt_bytecode_into(&encrypted, &key, None, &mut decrypted, None);
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("decryption failed"));
        }
    }

    #[test]
    fn test_corrupted_tag_fails() {
        let bytecode = b"test data";
        let key = test_key();
        let nonce = test_nonce();

        let mut encrypted = Vec::new();
        encrypt_bytecode_into(bytecode, Some(nonce), &key, 0, b"", &mut encrypted)
            .expect("encryption failed");

        // Corrupt the tag (bytes after nonce, before ciphertext)
        let tag_start = MAGIC.len()
            + 2 // version + aead_id
            + 2 // key_id
            + 4 + 4 // ad_len + ct_len
            + NONCE_LEN;
        if encrypted.len() > tag_start {
            encrypted[tag_start] ^= 0xFF;
            let mut decrypted = Vec::new();
            let result = decrypt_bytecode_into(&encrypted, &key, None, &mut decrypted, None);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_key_id_boundary_values() {
        let bytecode = b"test";
        let key = test_key();
        let nonce = test_nonce();

        for key_id in [0u16, 1, 256, 32768, u16::MAX] {
            let mut encrypted = Vec::new();
            encrypt_bytecode_into(bytecode, Some(nonce), &key, key_id, b"", &mut encrypted)
                .expect("encryption failed");

            let mut decrypted = Vec::new();
            decrypt_bytecode_into(&encrypted, &key, Some(key_id), &mut decrypted, None)
                .expect("decryption failed");

            assert_eq!(decrypted, bytecode);
        }
    }

    #[test]
    fn test_aad_appears_in_output() {
        let bytecode = b"code";
        let aad = b"my metadata";
        let key = test_key();
        let nonce = test_nonce();

        let mut encrypted = Vec::new();
        encrypt_bytecode_into(bytecode, Some(nonce), &key, 0, aad, &mut encrypted)
            .expect("encryption failed");

        // AAD should be at the end of the output
        assert!(encrypted.ends_with(aad));
    }

    #[test]
    fn test_nonce_in_output() {
        let bytecode = b"code";
        let key = test_key();
        let nonce = test_nonce();

        let mut encrypted = Vec::new();
        encrypt_bytecode_into(bytecode, Some(nonce), &key, 0, b"", &mut encrypted)
            .expect("encryption failed");

        // Nonce should be in the output at a known position
        let nonce_position = MAGIC.len() + 2 + 2 + 4 + 4;
        assert_eq!(&encrypted[nonce_position..nonce_position + NONCE_LEN], &nonce[..]);
    }
}
