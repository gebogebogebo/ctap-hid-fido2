use crate::pintoken::PinToken;

use super::{cose::CoseKey, p256};
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{anyhow, Error, Result};
use block_padding;
use hkdf::Hkdf;
use ring::rand::SecureRandom;
use ring::{agreement, digest, rand};
use sha2::Sha256;

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
        let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .map_err(Error::msg)?;
        let my_public_key_bytes = my_private_key.compute_public_key().map_err(Error::msg)?;

        let peer_public_key_bytes = p256::P256Key::from_cose(peer_key)?.bytes();
        let peer_public_key =
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &peer_public_key_bytes);

        let result_of_agree =
            agreement::agree_ephemeral(my_private_key, &peer_public_key, |material| {
                material.try_into().map_err(|_| ring::error::Unspecified)
            })
            .map_err(Error::msg)?;

        let shared_secret_z =
            result_of_agree.map_err(|_| anyhow!("Failed to convert material to array"))?;

        let secret = kdf(&shared_secret_z)?;

        let public_key = p256::P256Key::from_bytes(my_public_key_bytes.as_ref())?.to_cose();

        Ok(SharedSecret2 { secret, public_key })
    }

    pub fn encrypt_pin(&self, pin: &str) -> Result<Vec<u8>, String> {
        // Generate demPlaintext from pin
        let hash = digest::digest(&digest::SHA256, pin.as_bytes());
        let dem_plaintext = &hash.as_ref()[0..16];

        //
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinProto2
        //
        // 6.5.7. PIN/UV Auth Protocol Two
        // [encrypt(key, demPlaintext) → ciphertext]
        //

        // 1. Discard the first 32 bytes of key. (This selects the AES-key portion of the shared secret.)
        // Get AES key from the second half of self.secret
        let aes_key = &self.secret[32..];

        // 2. Let iv be a 16-byte, random bytestring.
        let mut iv = [0u8; 16];
        let rng = rand::SystemRandom::new();
        rng.fill(&mut iv).map_err(|e| e.to_string())?;

        // 3. Let ct be the AES-256-CBC encryption of demPlaintext using key and iv. (No padding is performed as the size of demPlaintext is required to be a multiple of the AES block length.)
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        let mut cipher = Aes256CbcEnc::new(aes_key.into(), &iv.into());
        let mut block = *GenericArray::from_slice(dem_plaintext);
        cipher.encrypt_block_mut(&mut block);
        let ciphertext = block.to_vec();

        // 4. Return iv || ct.
        // Concatenate iv and ct(ciphertext)
        let mut result = vec![];
        result.extend_from_slice(&iv);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt_token(&self, dem_cipher_text: &[u8]) -> Result<PinToken> {
        //
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinProto2
        //
        // 6.5.7. PIN/UV Auth Protocol Two
        // decrypt(key, demCiphertext) → plaintext | error
        //

        // 1. Discard the first 32 bytes of key. (This selects the AES-key portion of the shared secret.)
        // Get AES key
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
        if ciphertext.len() % 16 != 0 {
            return Err(anyhow!(
                "ciphertext length is not a multiple of the block size"
            ));
        }

        // 4. Return the AES-256-CBC decryption of ct using key and iv.
        type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
        let cipher = Aes256CbcDec::new(aes_key.into(), iv.into());

        let mut buf = ciphertext.to_vec();
        cipher
            .decrypt_padded_mut::<block_padding::NoPadding>(&mut buf)
            .map_err(|e| anyhow!(e))?;

        // return
        let pin_token = PinToken::new(&buf);
        Ok(pin_token)
    }
}

#[cfg(test)]
mod tests {
    use super::{kdf, CoseKey, SharedSecret2};

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
        use ring::digest;
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
}
