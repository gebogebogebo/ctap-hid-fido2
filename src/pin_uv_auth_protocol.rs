use crate::encrypt::cose::CoseKey;
use crate::encrypt::enc_hmac_sha_256;
use crate::encrypt::shared_secret::SharedSecret;
use crate::encrypt::shared_secret2::SharedSecret2;
use crate::pintoken::PinToken;
use anyhow::{anyhow, Result};

/// The CTAP2 PIN/UV Auth Protocol negotiated with the authenticator.
/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinProto
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinUvAuthProtocol {
    One,
    Two,
}

impl PinUvAuthProtocol {
    /// The single source of truth for which pin_protocol_version values are valid.
    pub fn from_version(pin_protocol_version: u8) -> Result<Self> {
        match pin_protocol_version {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            _ => Err(anyhow!("unknown pin_protocol_version")),
        }
    }

    pub fn version(&self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }
}

/// pinUvAuthParam = authenticate(key, message), per the negotiated PIN/UV Auth Protocol.
///
/// - Protocol One (6.5.7. authenticate): LEFT(HMAC-SHA-256(key, message), 16)
/// - Protocol Two (6.5.8. authenticate): HMAC-SHA-256(key, message) (32 bytes, untruncated)
pub fn compute_pin_uv_auth_param(
    key: &[u8],
    message: &[u8],
    pin_protocol_version: u8,
) -> Result<Vec<u8>> {
    let protocol = PinUvAuthProtocol::from_version(pin_protocol_version)?;
    let sig = enc_hmac_sha_256::authenticate(key, message);
    match protocol {
        PinUvAuthProtocol::One => Ok(sig[0..16].to_vec()),
        PinUvAuthProtocol::Two => Ok(sig),
    }
}

/// A PIN/UV Auth Protocol shared secret, in whichever protocol version was negotiated.
///
/// Centralizes the Protocol One vs Protocol Two split (key material, encrypt/decrypt,
/// and HMAC truncation rules) so callers that need a shared secret — for the
/// pinUvAuthToken flow, PIN set/change, or an extension like hmac-secret — don't have
/// to re-implement the split themselves.
#[derive(Debug, Clone)]
pub enum PinUvAuthSharedSecret {
    One(SharedSecret),
    Two(SharedSecret2),
}

impl Default for PinUvAuthSharedSecret {
    fn default() -> Self {
        Self::One(SharedSecret::default())
    }
}

impl PinUvAuthSharedSecret {
    pub fn new(pin_protocol_version: u8, key_agreement: &CoseKey) -> Result<Self> {
        match PinUvAuthProtocol::from_version(pin_protocol_version)? {
            PinUvAuthProtocol::One => Ok(Self::One(SharedSecret::new(key_agreement)?)),
            PinUvAuthProtocol::Two => Ok(Self::Two(SharedSecret2::new(key_agreement)?)),
        }
    }

    pub fn public_key(&self) -> &CoseKey {
        match self {
            Self::One(s) => &s.public_key,
            Self::Two(s) => &s.public_key,
        }
    }

    pub fn pin_protocol_version(&self) -> u8 {
        match self {
            Self::One(_) => PinUvAuthProtocol::One.version(),
            Self::Two(_) => PinUvAuthProtocol::Two.version(),
        }
    }

    /// The key used for authenticate()/HMAC-SHA-256. Protocol Two discards the
    /// AES-key half of the shared secret, keeping only the HMAC-key half.
    fn auth_key(&self) -> &[u8] {
        match self {
            Self::One(s) => &s.secret,
            Self::Two(s) => &s.secret[0..32],
        }
    }

    /// encrypt(key, demPlaintext) → ciphertext, per the negotiated protocol version.
    pub fn encrypt(&self, dem_plaintext: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::One(s) => Ok(s.encrypt_raw(dem_plaintext)),
            Self::Two(s) => s.encrypt(dem_plaintext),
        }
    }

    /// decrypt(key, demCiphertext) → plaintext, per the negotiated protocol version.
    pub fn decrypt(&self, dem_cipher_text: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::One(s) => Ok(s.decrypt_raw(dem_cipher_text)),
            Self::Two(s) => s.decrypt(dem_cipher_text),
        }
    }

    /// authenticate(key, message) → pinUvAuthParam, per the negotiated protocol version.
    pub fn authenticate(&self, message: &[u8]) -> Result<Vec<u8>> {
        compute_pin_uv_auth_param(self.auth_key(), message, self.pin_protocol_version())
    }

    /// pinHashEnc/pinUvAuthToken encryption of a raw PIN string, per the negotiated
    /// protocol version's PIN-hashing rule (LEFT(SHA-256(pin), 16), then encrypt()).
    pub fn encrypt_pin(&self, pin: &str) -> Result<Vec<u8>> {
        match self {
            Self::One(s) => Ok(s.encrypt_pin(pin)?.to_vec()),
            Self::Two(s) => s.encrypt_pin(pin),
        }
    }

    /// Decrypt an authenticator-provided pinUvAuthToken ciphertext into a PinToken.
    pub fn decrypt_token(&self, dem_cipher_text: &[u8]) -> Result<PinToken> {
        match self {
            Self::One(s) => s.decrypt_token(dem_cipher_text),
            Self::Two(s) => s.decrypt_token(dem_cipher_text),
        }
    }
}

#[cfg(test)]
mod pin_uv_auth_shared_secret_tests {
    use super::*;

    fn one() -> PinUvAuthSharedSecret {
        PinUvAuthSharedSecret::One(SharedSecret {
            secret: [3u8; 32],
            public_key: CoseKey::default(),
        })
    }

    fn two() -> PinUvAuthSharedSecret {
        let mut secret = [0u8; 64];
        secret[..32].copy_from_slice(&[1u8; 32]); // HMAC-key half
        secret[32..].copy_from_slice(&[2u8; 32]); // AES-key half
        PinUvAuthSharedSecret::Two(SharedSecret2 {
            secret,
            public_key: CoseKey::default(),
        })
    }

    #[test]
    fn test_pin_uv_auth_shared_secret_protocol_versions() {
        assert_eq!(one().pin_protocol_version(), 1);
        assert_eq!(two().pin_protocol_version(), 2);
    }

    #[test]
    fn test_pin_uv_auth_shared_secret_encrypt_decrypt_roundtrip() {
        let salt = [9u8; 32];

        for shared_secret in [one(), two()] {
            let salt_enc = shared_secret.encrypt(&salt).unwrap();
            let decrypted = shared_secret.decrypt(&salt_enc).unwrap();
            assert_eq!(decrypted, salt);
        }
    }

    #[test]
    fn test_pin_uv_auth_shared_secret_authenticate_length() {
        let message = [5u8; 32];

        // Protocol One truncates to 16 bytes.
        let param_one = one().authenticate(&message).unwrap();
        assert_eq!(param_one.len(), 16);

        // Protocol Two returns the full 32-byte HMAC-SHA-256 output.
        let param_two = two().authenticate(&message).unwrap();
        assert_eq!(param_two.len(), 32);
    }

    #[test]
    fn test_pin_uv_auth_shared_secret_new_rejects_unknown_protocol() {
        let result = PinUvAuthSharedSecret::new(3, &CoseKey::default());
        assert!(result.is_err());
    }
}
