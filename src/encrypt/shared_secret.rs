use crate::crypto::{agreement, digest, rand};
use crate::{encrypt::cose::CoseKey, encrypt::enc_aes256_cbc, encrypt::p256, pintoken::PinToken};
use anyhow::{Error, Result};

#[derive(Debug, Default, Clone)]
pub struct SharedSecret {
    pub public_key: CoseKey,
    pub secret: [u8; 32],
}

impl SharedSecret {
    pub fn new(peer_key: &CoseKey) -> Result<Self> {
        let rng = rand::SystemRandom::new();
        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(Error::msg)?;

        let my_public_key = my_private_key.compute_public_key().map_err(Error::msg)?;

        let peer_public_key = {
            let peer_public_key = p256::P256Key::from_cose(peer_key)?.bytes();
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public_key)
        };

        let shared_secret =
            crate::crypto::agree_ephemeral(my_private_key, &peer_public_key, |material| {
                digest::digest(&digest::SHA256, material)
            })
            .map_err(Error::msg)?;

        let mut res = SharedSecret {
            public_key: p256::P256Key::from_bytes(my_public_key.as_ref())?.to_cose(),
            secret: [0; 32],
        };
        res.secret.copy_from_slice(shared_secret.as_ref());

        Ok(res)
    }

    pub fn encrypt_pin(&self, pin: &str) -> Result<[u8; 16]> {
        self.encrypt(pin.as_bytes())
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<[u8; 16]> {
        let hash = digest::digest(&digest::SHA256, data);
        let message = &hash.as_ref()[0..16];
        let enc = enc_aes256_cbc::encrypt_message(&self.secret, message);
        let mut out_bytes = [0; 16];
        out_bytes.copy_from_slice(&enc[0..16]);
        Ok(out_bytes)
    }

    pub fn decrypt_token(&self, data: &[u8]) -> Result<PinToken> {
        let dec = enc_aes256_cbc::decrypt_message(&self.secret, data);
        let pin_token = PinToken::new(&dec);
        Ok(pin_token)
    }

    /// 6.5.6. PIN/UV Auth Protocol One: encrypt(key, demPlaintext) → ciphertext
    /// AES-256-CBC(key, IV=0, demPlaintext), no padding.
    pub fn encrypt_raw(&self, dem_plaintext: &[u8]) -> Vec<u8> {
        enc_aes256_cbc::encrypt_message(&self.secret, dem_plaintext)
    }

    /// 6.5.6. PIN/UV Auth Protocol One: decrypt(key, demCiphertext) → plaintext
    /// AES-256-CBC(key, IV=0, demCiphertext), no padding.
    pub fn decrypt_raw(&self, dem_cipher_text: &[u8]) -> Vec<u8> {
        enc_aes256_cbc::decrypt_message(&self.secret, dem_cipher_text)
    }
}
