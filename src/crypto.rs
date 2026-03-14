#[cfg(all(feature = "ring", feature = "aws-lc-rs"))]
compile_error!("Features `ring` and `aws-lc-rs` are mutually exclusive.");

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs")))]
compile_error!("Enable one crypto backend: `ring` or `aws-lc-rs`.");

#[cfg(feature = "ring")]
pub use ring::{agreement, digest, error, hkdf, hmac, rand, signature};

#[cfg(feature = "aws-lc-rs")]
pub use aws_lc_rs::{agreement, digest, error, hkdf, hmac, rand, signature};

/// Wrapper around `agree_ephemeral` that normalizes the different
/// function signatures between `ring` and `aws-lc-rs`.
///
/// `ring` signature:
///   `agree_ephemeral(key, peer, kdf: FnOnce(&[u8]) -> R) -> Result<R, Unspecified>`
///
/// `aws-lc-rs` signature:
///   `agree_ephemeral(key, peer, err, kdf: FnOnce(&[u8]) -> Result<R, E>) -> Result<R, E>`
#[cfg(feature = "ring")]
pub fn agree_ephemeral<B, F, R>(
    my_private_key: agreement::EphemeralPrivateKey,
    peer_public_key: &agreement::UnparsedPublicKey<B>,
    kdf: F,
) -> Result<R, error::Unspecified>
where
    B: AsRef<[u8]>,
    F: FnOnce(&[u8]) -> R,
{
    agreement::agree_ephemeral(my_private_key, peer_public_key, kdf)
}

#[cfg(feature = "aws-lc-rs")]
pub fn agree_ephemeral<B, F, R>(
    my_private_key: agreement::EphemeralPrivateKey,
    peer_public_key: &agreement::UnparsedPublicKey<B>,
    kdf: F,
) -> Result<R, error::Unspecified>
where
    B: AsRef<[u8]>,
    F: FnOnce(&[u8]) -> R,
{
    agreement::agree_ephemeral(
        my_private_key,
        peer_public_key,
        error::Unspecified,
        |material| Ok(kdf(material)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- SHA-256 (digest) ---

    #[test]
    fn sha256_known_vector() {
        // NIST FIPS 180-4 test vector for "abc"
        let expected = [
            0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE,
            0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61,
            0xF2, 0x00, 0x15, 0xAD,
        ];
        let result = digest::digest(&digest::SHA256, b"abc");
        assert_eq!(result.as_ref(), &expected);
    }

    #[test]
    fn sha256_empty_input() {
        // SHA-256("") is a well-known constant
        let expected = [
            0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F,
            0xB9, 0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B,
            0x78, 0x52, 0xB8, 0x55,
        ];
        let result = digest::digest(&digest::SHA256, b"");
        assert_eq!(result.as_ref(), &expected);
    }

    // --- HMAC-SHA-256 ---

    #[test]
    fn hmac_sha256_known_vector() {
        // RFC 4231 Test Case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = [
            0x5B, 0xDC, 0xC1, 0x46, 0xBF, 0x60, 0x75, 0x4E, 0x6A, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xC7, 0x5A, 0x00, 0x3F, 0x08, 0x9D, 0x27, 0x39, 0x83, 0x9D, 0xEC, 0x58, 0xB9,
            0x64, 0xEC, 0x38, 0x43,
        ];
        let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
        let tag = hmac::sign(&hmac_key, data);
        assert_eq!(tag.as_ref(), &expected);
    }

    #[test]
    fn hmac_sha256_verify_roundtrip() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"test-key-material");
        let tag = hmac::sign(&key, b"message");
        assert!(hmac::verify(&key, b"message", tag.as_ref()).is_ok());
        assert!(hmac::verify(&key, b"tampered", tag.as_ref()).is_err());
    }

    // --- HKDF-SHA-256 ---

    #[test]
    fn hkdf_sha256_deterministic() {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[0u8; 32]);
        let prk = salt.extract(&[0xAB; 32]);

        let mut out1 = [0u8; 32];
        prk.expand(&[b"info"], hkdf::HKDF_SHA256)
            .and_then(|okm| okm.fill(&mut out1))
            .expect("HKDF expand failed");

        // Same inputs must produce same output
        let prk2 = salt.extract(&[0xAB; 32]);
        let mut out2 = [0u8; 32];
        prk2.expand(&[b"info"], hkdf::HKDF_SHA256)
            .and_then(|okm| okm.fill(&mut out2))
            .expect("HKDF expand failed");

        assert_eq!(out1, out2);

        // Different info must produce different output
        let mut out3 = [0u8; 32];
        prk.expand(&[b"other"], hkdf::HKDF_SHA256)
            .and_then(|okm| okm.fill(&mut out3))
            .expect("HKDF expand failed");

        assert_ne!(out1, out3);
    }

    // --- ECDH P-256 key agreement ---

    #[test]
    fn ecdh_p256_key_generation() {
        let rng = rand::SystemRandom::new();
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .expect("key generation failed");
        let public_key = private_key
            .compute_public_key()
            .expect("compute public key failed");

        // P-256 uncompressed point: 0x04 || x (32 bytes) || y (32 bytes) = 65 bytes
        assert_eq!(public_key.as_ref().len(), 65);
        assert_eq!(public_key.as_ref()[0], 0x04);
    }

    #[test]
    fn ecdh_p256_agree_ephemeral() {
        let rng = rand::SystemRandom::new();

        // Generate two key pairs
        let my_private = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .expect("key generation failed");
        let my_public = my_private
            .compute_public_key()
            .expect("compute public key failed");

        let peer_private = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
            .expect("key generation failed");
        let peer_public = peer_private
            .compute_public_key()
            .expect("compute public key failed");

        // Perform key agreement: my_private + peer_public
        let peer_unparsed =
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, peer_public.as_ref());
        let shared1 = agree_ephemeral(my_private, &peer_unparsed, |material| material.to_vec())
            .expect("agree_ephemeral failed");

        // Perform key agreement: peer_private + my_public
        let my_unparsed =
            agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, my_public.as_ref());
        let shared2 = agree_ephemeral(peer_private, &my_unparsed, |material| material.to_vec())
            .expect("agree_ephemeral failed");

        // Both sides must derive the same shared secret
        assert_eq!(shared1, shared2);
        assert_eq!(shared1.len(), 32);
    }

    // --- ECDSA P-256 signature verification ---

    #[test]
    fn ecdsa_p256_sign_and_verify() {
        use signature::KeyPair;

        let rng = rand::SystemRandom::new();

        let doc = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &rng,
        )
        .expect("keygen failed");

        #[cfg(feature = "ring")]
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            doc.as_ref(),
            &rng,
        )
        .expect("parse pkcs8 failed");

        #[cfg(feature = "aws-lc-rs")]
        let key_pair = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            doc.as_ref(),
        )
        .expect("parse pkcs8 failed");

        let message = b"FIDO2 test message for signature verification";
        let sig = key_pair.sign(&rng, message).expect("signing failed");

        // Verify with the public key
        let public_key_bytes = key_pair.public_key().as_ref();
        let verify_key =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key_bytes);
        assert!(verify_key.verify(message, sig.as_ref()).is_ok());

        // Tampered message must fail
        assert!(verify_key.verify(b"tampered", sig.as_ref()).is_err());

        // Tampered signature must fail
        let mut bad_sig = sig.as_ref().to_vec();
        if let Some(last) = bad_sig.last_mut() {
            *last ^= 0xFF;
        }
        assert!(verify_key.verify(message, &bad_sig).is_err());
    }

    // --- Ed25519 signature verification ---

    #[test]
    fn ed25519_verify_rfc8032_test1() {
        // RFC 8032 Section 7.1 - TEST 1 (empty message)
        let public_key_bytes =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        let message = b"";
        let sig_bytes = hex::decode(concat!(
            "e5564300c360ac729086e2cc806e828a",
            "84877f1eb8e5d974d873e06522490155",
            "5fb8821590a33bacc61e39701cf9b46b",
            "d25bf5f0595bbe24655141438e7a100b",
        ))
        .unwrap();

        let verify_key = signature::UnparsedPublicKey::new(&signature::ED25519, &public_key_bytes);
        assert!(verify_key.verify(message, &sig_bytes).is_ok());
        assert!(verify_key.verify(b"tampered", &sig_bytes).is_err());
    }

    #[test]
    fn ed25519_verify_rfc8032_test2() {
        // RFC 8032 Section 7.1 - TEST 2 (single byte 0x72)
        let public_key_bytes =
            hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .unwrap();
        let message = hex::decode("72").unwrap();
        let sig_bytes = hex::decode(concat!(
            "92a009a9f0d4cab8720e820b5f642540",
            "a2b27b5416503f8fb3762223ebdb69da",
            "085ac1e43e15996e458f3613d0f11d8c",
            "387b2eaeb4302aeeb00d291612bb0c00",
        ))
        .unwrap();

        let verify_key = signature::UnparsedPublicKey::new(&signature::ED25519, &public_key_bytes);
        assert!(verify_key.verify(&message, &sig_bytes).is_ok());
        assert!(verify_key.verify(b"tampered", &sig_bytes).is_err());
    }

    // --- Random number generation ---

    #[test]
    fn system_random_fills_buffer() {
        use rand::SecureRandom;

        let rng = rand::SystemRandom::new();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf).expect("fill failed");

        // Extremely unlikely that 32 random bytes are all zero
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn system_random_produces_different_values() {
        use rand::SecureRandom;

        let rng = rand::SystemRandom::new();
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        rng.fill(&mut buf1).expect("fill failed");
        rng.fill(&mut buf2).expect("fill failed");

        // Two random 32-byte fills should differ (probability of collision: 2^-256)
        assert_ne!(buf1, buf2);
    }
}
