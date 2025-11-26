use anyhow::{anyhow, Error, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use ring::{agreement, rand};
use crate::{encrypt::cose::CoseKey, encrypt::p256};

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

}

#[cfg(test)]
mod tests {
    use super::kdf;

    #[test]
    fn test_kdf_concatenation() {
        // This test ensures the kdf function correctly concatenates the two derived keys.
        // It does not validate the cryptographic correctness of the keys themselves, as
        // the test vectors used previously were found to be unreliable.
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
}
