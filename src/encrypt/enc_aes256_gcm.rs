use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Nonce,
};
use anyhow::{anyhow, Result};

pub fn encrypt_message(key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
    let key = key.into();
    let cipher = Aes256Gcm::new(key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, message).map_err(|e| anyhow!(e))?;

    let mut result = vec![];
    result.extend_from_slice(nonce.as_slice());
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt_message(key: &[u8], encrypted_message: &[u8]) -> Result<Vec<u8>> {
    let key = key.into();
    let cipher = Aes256Gcm::new(key);

    if encrypted_message.len() < 12 {
        return Err(anyhow!("Invalid encrypted message length"));
    }

    let (nonce_slice, ciphertext_slice) = encrypted_message.split_at(12);
    let nonce = Nonce::from_slice(nonce_slice);

    let plaintext = cipher
        .decrypt(nonce, ciphertext_slice)
        .map_err(|e| anyhow!(e))?;

    Ok(plaintext)
}
