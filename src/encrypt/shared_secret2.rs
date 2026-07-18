use crate::encrypt::enc_aes256_cbc;
use crate::pintoken::PinToken;

use super::{cose::CoseKey, p256};

use crate::crypto::rand::SecureRandom;
use anyhow::{anyhow, Error, Result};

use crate::crypto::{agreement, digest, hkdf, rand};

#[derive(Debug, Clone)]
pub struct SharedSecret2 {
    pub secret: [u8; 64],
    pub public_key: CoseKey,
}

fn kdf(z: &[u8; 32]) -> Result<[u8; 64]> {
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[0u8; 32]);
    let prk = salt.extract(z);

    let mut hmac_key = [0u8; 32];
    prk.expand(&[b"CTAP2 HMAC key"], hkdf::HKDF_SHA256)
        .and_then(|okm| okm.fill(&mut hmac_key))
        .map_err(|_| anyhow!("HKDF expand for HMAC key failed"))?;

    let mut aes_key = [0u8; 32];
    prk.expand(&[b"CTAP2 AES key"], hkdf::HKDF_SHA256)
        .and_then(|okm| okm.fill(&mut aes_key))
        .map_err(|_| anyhow!("HKDF expand for AES key failed"))?;

    let mut secret = [0u8; 64];
    secret[..32].copy_from_slice(&hmac_key);
    secret[32..].copy_from_slice(&aes_key);

    Ok(secret)
}

impl SharedSecret2 {
    pub fn new(peer_key: &CoseKey) -> Result<Self> {
        let rng = rand::SystemRandom::new();
        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(Error::msg)?;
        let my_public_key_bytes = my_private_key.compute_public_key().map_err(Error::msg)?;

        let peer_public_key_bytes = p256::P256Key::from_cose(peer_key)?.bytes();
        let peer_public_key =
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &peer_public_key_bytes);

        let shared_secret_bytes =
            crate::crypto::agree_ephemeral(my_private_key, &peer_public_key, |material| {
                material.to_vec()
            })
            .map_err(Error::msg)?;

        let shared_secret_z: [u8; 32] = shared_secret_bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow!("ECDH P-256 shared secret must be 32 bytes, got {}", v.len())
        })?;

        let secret = kdf(&shared_secret_z)?;

        let public_key = p256::P256Key::from_bytes(my_public_key_bytes.as_ref())?.to_cose();

        Ok(SharedSecret2 { secret, public_key })
    }

    pub fn encrypt_pin(&self, pin: &str) -> Result<Vec<u8>> {
        // Generate demPlaintext from pin
        let hash = digest::digest(&digest::SHA256, pin.as_bytes());
        let dem_plaintext = &hash.as_ref()[0..16];
        self.encrypt(dem_plaintext)
    }

    /// 6.5.7. PIN/UV Auth Protocol Two: encrypt(key, demPlaintext) → ciphertext
    /// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinProto2
    ///
    /// `demPlaintext` must be a multiple of the AES block length (16 bytes); no padding is performed.
    pub fn encrypt(&self, dem_plaintext: &[u8]) -> Result<Vec<u8>> {
        // 1. Discard the first 32 bytes of key. (This selects the AES-key portion of the shared secret.)
        let aes_key = &self.secret[32..];

        // 2. Let iv be a 16-byte, random bytestring.
        let mut iv = [0u8; 16];
        let rng = rand::SystemRandom::new();
        rng.fill(&mut iv)
            .map_err(|_| anyhow!("Failed to generate random IV"))?;

        // 3. Let ct be the AES-256-CBC encryption of demPlaintext using key and iv.
        let ciphertext = enc_aes256_cbc::encrypt_message_with_iv(aes_key, &iv, dem_plaintext);

        // 4. Return iv || ct.
        let mut result = vec![];
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt_token(&self, dem_cipher_text: &[u8]) -> Result<PinToken> {
        Ok(PinToken::new(&self.decrypt(dem_cipher_text)?))
    }

    /// 6.5.7. PIN/UV Auth Protocol Two: decrypt(key, demCiphertext) → plaintext | error
    /// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinProto2
    pub fn decrypt(&self, dem_cipher_text: &[u8]) -> Result<Vec<u8>> {
        // 1. Discard the first 32 bytes of key. (This selects the AES-key portion of the shared secret.)
        let aes_key = &self.secret[32..];

        // 2. If demPlaintext is less than 16 bytes in length, return an error
        // (Specify demCiphertext instead of demPlaintext)
        if dem_cipher_text.len() < 16 {
            return Err(anyhow!("demCiphertext must be at least 16 bytes"));
        }

        // 3. Split demPlaintext after the 16th byte to produce two subspans, iv and ct.
        // (Specify demCiphertext instead of demPlaintext)
        let iv = &dem_cipher_text[0..16];
        let ciphertext = &dem_cipher_text[16..];
        if !ciphertext.len().is_multiple_of(16) {
            return Err(anyhow!(
                "ciphertext length is not a multiple of the block size"
            ));
        }

        // 4. Return the AES-256-CBC decryption of ct using key and iv.
        Ok(enc_aes256_cbc::decrypt_message_with_iv(aes_key, iv, ciphertext))
    }
}

#[cfg(test)]
mod tests {
    use super::{kdf, CoseKey, SharedSecret2};
    use crate::crypto::hkdf;

    #[test]
    fn test_kdf_concatenation() {
        let z = [1u8; 32];
        let shared_secret = kdf(&z).unwrap();

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[0u8; 32]);
        let prk = salt.extract(&z);

        let mut hmac_key = [0u8; 32];
        prk.expand(&[b"CTAP2 HMAC key"], hkdf::HKDF_SHA256)
            .and_then(|okm| okm.fill(&mut hmac_key))
            .unwrap();

        let mut aes_key = [0u8; 32];
        prk.expand(&[b"CTAP2 AES key"], hkdf::HKDF_SHA256)
            .and_then(|okm| okm.fill(&mut aes_key))
            .unwrap();

        let mut expected_secret = [0u8; 64];
        expected_secret[..32].copy_from_slice(&hmac_key);
        expected_secret[32..].copy_from_slice(&aes_key);
        assert_eq!(shared_secret, expected_secret);
    }

    #[test]
    fn test_encrypt_pin_and_decrypt_token() {
        let mut secret = [0u8; 64];
        secret[32..].copy_from_slice(&[1u8; 32]); // Use a known key for the test
        let ss2 = SharedSecret2 {
            secret,
            public_key: CoseKey::default(),
        };

        let pin = "1234";
        let encrypted_data = ss2.encrypt_pin(pin).unwrap();

        // Decrypt and verify
        let pin_token = ss2.decrypt_token(&encrypted_data).unwrap();
        use crate::crypto::digest;
        let hash = digest::digest(&digest::SHA256, pin.as_bytes());
        let expected_plaintext = &hash.as_ref()[0..16];
        assert_eq!(pin_token.key, expected_plaintext);
    }

    #[test]
    fn test_decrypt_token_invalid_length() {
        let ss2 = SharedSecret2 {
            secret: [0u8; 64],

            public_key: CoseKey::default(),
        };
        let data = vec![0u8; 15]; // Less than 16 bytes
        let result = ss2.decrypt_token(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_hmac_secret_salt() {
        // hmac-secret salts are raw 32-or-64-byte plaintext, not a PIN hash,
        // so this exercises encrypt()/decrypt() directly rather than via encrypt_pin/decrypt_token.
        let mut secret = [0u8; 64];
        secret[32..].copy_from_slice(&[7u8; 32]);
        let ss2 = SharedSecret2 {
            secret,
            public_key: CoseKey::default(),
        };

        let salt = [9u8; 32]; // single hmac-secret salt
        let salt_enc = ss2.encrypt(&salt).unwrap();
        assert_eq!(salt_enc.len(), 16 + salt.len()); // iv || ciphertext

        let decrypted = ss2.decrypt(&salt_enc).unwrap();
        assert_eq!(decrypted, salt);
    }
}
