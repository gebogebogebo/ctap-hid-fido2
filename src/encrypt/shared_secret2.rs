use crate::{pintoken::PinToken};

use anyhow::{anyhow, Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use ring::{agreement, digest, rand};
use ring::rand::SecureRandom;
use super::{cose::CoseKey, p256};
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes::cipher::generic_array::GenericArray;

pub struct SharedSecret2 {
    pub secret: [u8; 64],
    pub public_key: CoseKey,
}

fn kdf(z: &[u8; 32]) -> Result<[u8; 64]> {
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), z);

    let mut hmac_key = [0u8; 32];
    hk.expand(b"CTAP2 HMAC key", &mut hmac_key)
        .map_err(|e| anyhow!("HKDF expand for HMAC key failed: {:?}", e))?;

    let mut aes_key = [0u8; 32];
    hk.expand(b"CTAP2 AES key", &mut aes_key)
        .map_err(|e| anyhow!("HKDF expand for AES key failed: {:?}", e))?;

    let mut secret = [0u8; 64];
    secret[..32].copy_from_slice(&hmac_key);
    secret[32..].copy_from_slice(&aes_key);

    Ok(secret)
}

impl SharedSecret2 {
    pub fn new(peer_key: &CoseKey) -> Result<Self> {
        let rng = rand::SystemRandom::new();
        let my_private_key =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).map_err(Error::msg)?;
        let my_public_key_bytes = my_private_key.compute_public_key().map_err(Error::msg)?;

        let peer_public_key_bytes = p256::P256Key::from_cose(peer_key)?.bytes();
        let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &peer_public_key_bytes);

        let result_of_agree = agreement::agree_ephemeral(
            my_private_key,
            &peer_public_key,
            |material| material.try_into().map_err(|_| ring::error::Unspecified)
        ).map_err(Error::msg)?;

        let shared_secret_z = result_of_agree.map_err(|_| anyhow!("Failed to convert material to array"))?;

        let secret = kdf(&shared_secret_z)?;

        let public_key = p256::P256Key::from_bytes(my_public_key_bytes.as_ref())?.to_cose();

        Ok(SharedSecret2 { secret, public_key })
    }

    pub fn encrypt_pin(&self, pin: &str) -> Result<Vec<u8>, String> {
        // Generate demPlaintext from pin
        let hash = digest::digest(&digest::SHA256, pin.as_bytes());
        let dem_plaintext = &hash.as_ref()[0..16];

        // Get AES key from the second half of self.secret
        let aes_key = &self.secret[32..];

        // Generate random 16-byte IV
        let mut iv = [0u8; 16];
        let rng = rand::SystemRandom::new();
        rng.fill(&mut iv).map_err(|e| e.to_string())?;

        // Encrypt with AES-256-CBC, no padding
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        let mut cipher = Aes256CbcEnc::new(aes_key.into(), &iv.into());
        
        let mut block = *GenericArray::from_slice(dem_plaintext);
        cipher.encrypt_block_mut(&mut block);
        let ciphertext = block.to_vec();

        // Concatenate IV and ciphertext
        let mut result = vec![];
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt_token(&self, data: &mut [u8]) -> Result<PinToken> {
        // TODO
    }

}

#[cfg(test)]
mod tests {
    use super::{kdf, SharedSecret2, CoseKey};

    #[test]
    fn test_kdf_concatenation() {
        let z = [1u8; 32];
        let shared_secret = kdf(&z).unwrap();

        use hkdf::Hkdf;
        use sha2::Sha256;

        let salt = [0u8; 32];
        let hk = Hkdf::<Sha256>::new(Some(&salt), &z);
        let mut hmac_key = [0u8; 32];
        hk.expand(b"CTAP2 HMAC key", &mut hmac_key).unwrap();
        let mut aes_key = [0u8; 32];
        hk.expand(b"CTAP2 AES key", &mut aes_key).unwrap();

        let mut expected_secret = [0u8; 64];
        expected_secret[..32].copy_from_slice(&hmac_key);
        expected_secret[32..].copy_from_slice(&aes_key);

        assert_eq!(shared_secret, expected_secret);
    }

    #[test]
    fn test_encrypt_pin() {
        use aes::cipher::generic_array::GenericArray;
        let mut secret = [0u8; 64];
        secret[32..].copy_from_slice(&[1u8; 32]); // Use a known key for the test

        let ss2 = SharedSecret2 {
            secret,
            public_key: CoseKey::default(),
        };

        let pin = "1234";
        let encrypted_data1 = ss2.encrypt_pin(pin).unwrap();
        let encrypted_data2 = ss2.encrypt_pin(pin).unwrap();

        // 1. Check for random IV: outputs should be different
        assert_ne!(encrypted_data1, encrypted_data2);

        // 2. Check length: IV (16) + demPlaintext (16) = 32
        assert_eq!(encrypted_data1.len(), 32);

        // 3. Decrypt and verify
        let iv = &encrypted_data1[0..16];
        let ciphertext = &encrypted_data1[16..];
        let key = &ss2.secret[32..];

        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
        use aes::cipher::{KeyIvInit, BlockDecryptMut};

        let mut cipher = Aes256CbcDec::new(key.into(), iv.into());
        let mut block = *GenericArray::from_slice(ciphertext);
        cipher.decrypt_block_mut(&mut block);
        let decrypted_plaintext = block.to_vec();

        use ring::digest;
        let hash = digest::digest(&digest::SHA256, pin.as_bytes());
        let expected_plaintext = &hash.as_ref()[0..16];

        assert_eq!(decrypted_plaintext, expected_plaintext);
    }
}