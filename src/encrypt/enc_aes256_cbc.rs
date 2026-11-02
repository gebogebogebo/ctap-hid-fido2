use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use anyhow::{anyhow, Result};

// AES256-CBC(key,IV=0,message)
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

#[allow(dead_code)]
pub fn encrypt_message_str(key: &[u8; 32], message: &str) -> Vec<u8> {
    encrypt_message(key, message.as_bytes())
}

pub fn encrypt_message(key: &[u8; 32], message: &[u8]) -> Vec<u8> {
    if message.len() > 4096 {
        panic!("Message too long");
    }

    let mut buffer = message.to_vec();
    let pt_len = message.len();
    let zero_iv = [0u8; 16];
    let ciphertext = Aes256CbcEnc::new(&(*key).into(), &zero_iv.into())
        .encrypt_padded::<NoPadding>(&mut buffer, pt_len)
        .unwrap();
    ciphertext.to_vec()
}

pub fn encrypt_message_with_iv(key: &[u8], iv: &[u8], message: &[u8]) -> Vec<u8> {
    if message.len() > 4096 {
        panic!("Message too long");
    }

    let mut buffer = message.to_vec();
    let pt_len = message.len();
    let ciphertext = Aes256CbcEnc::new_from_slices(key, iv)
        .expect("AES-256-CBC requires a 32-byte key and 16-byte IV")
        .encrypt_padded::<NoPadding>(&mut buffer, pt_len)
        .unwrap();
    ciphertext.to_vec()
}

#[allow(dead_code)]
pub fn decrypt_message_str(key: &[u8; 32], message: &[u8]) -> Result<String> {
    let bytes = decrypt_message(key, message)?;
    Ok(String::from_utf8(bytes.to_vec()).unwrap())
}

/// The ciphertext passed to the decrypt functions usually comes from the
/// authenticator, so its length is untrusted: reject it with an error rather
/// than panicking.
fn check_ciphertext_len(message: &[u8]) -> Result<()> {
    if message.len() > 4096 {
        return Err(anyhow!("ciphertext too long"));
    }
    if !message.len().is_multiple_of(16) {
        return Err(anyhow!(
            "ciphertext length is not a multiple of the block size"
        ));
    }
    Ok(())
}

pub fn decrypt_message(key: &[u8; 32], message: &[u8]) -> Result<Vec<u8>> {
    check_ciphertext_len(message)?;

    let mut buffer = message.to_vec();
    let zero_iv = [0u8; 16];
    let plaintext = Aes256CbcDec::new(&(*key).into(), &zero_iv.into())
        .decrypt_padded::<NoPadding>(&mut buffer)
        .map_err(|_| anyhow!("AES-256-CBC decryption failed"))?;
    Ok(plaintext.to_vec())
}

pub fn decrypt_message_with_iv(key: &[u8], iv: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    check_ciphertext_len(message)?;

    let mut buffer = message.to_vec();
    let plaintext = Aes256CbcDec::new_from_slices(key, iv)
        .expect("AES-256-CBC requires a 32-byte key and 16-byte IV")
        .decrypt_padded::<NoPadding>(&mut buffer)
        .map_err(|_| anyhow!("AES-256-CBC decryption failed"))?;
    Ok(plaintext.to_vec())
}
