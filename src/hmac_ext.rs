use crate::ctaphid;
use crate::encrypt::cose::CoseKey;
use crate::encrypt::shared_secret::SharedSecret;
use crate::encrypt::shared_secret2::SharedSecret2;
use crate::fidokey::pin::{
    create_payload, parse_cbor_client_pin_get_keyagreement, SubCommand as PinCmd,
};
use crate::pin_uv_auth_protocol::{self, PinUvAuthProtocol};
use crate::FidoKeyHid;
use anyhow::Result;

/// A PIN/UV Auth Protocol shared secret, in whichever protocol version was negotiated.
///
/// Centralizes the Protocol One vs Protocol Two split (key material, encrypt/decrypt,
/// and HMAC truncation rules) so callers that need a shared secret for something other
/// than the pinUvAuthToken flow (e.g. the hmac-secret extension) don't have to
/// re-implement the split themselves.
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
        pin_uv_auth_protocol::compute_pin_uv_auth_param(
            self.auth_key(),
            message,
            self.pin_protocol_version(),
        )
    }
}

#[derive(Debug, Default, Clone)]
pub struct HmacExt {
    pub shared_secret: PinUvAuthSharedSecret,
    pub salt_enc: Vec<u8>,
    pub salt_auth: Vec<u8>,
    pub pin_protocol_version: u8,
}

impl HmacExt {
    pub fn create(
        &mut self,
        device: &FidoKeyHid,
        salt1: &[u8; 32],
        salt2: Option<&[u8; 32]>,
    ) -> Result<()> {
        let send_payload = create_payload(PinCmd::GetKeyAgreement, device.pin_protocol_version)?;
        let response_cbor = ctaphid::ctaphid_cbor(device, &send_payload)?;

        let key_agreement = parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

        let shared_secret =
            PinUvAuthSharedSecret::new(device.pin_protocol_version, &key_agreement)?;

        let mut salt = salt1.to_vec();
        if let Some(s) = salt2 {
            // println!("second salt");
            salt.extend_from_slice(s);
        }

        // saltEnc
        //  Encryption of the one or two salts (called salt1 (32 bytes)
        //  and salt2 (32 bytes)) using the shared secret as follows
        // One salt case: encrypt(shared secret, salt1)
        // Two salt case: encrypt(shared secret, salt1 || salt2)
        //  encrypt(key, demPlaintext) → ciphertext
        //      Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext.
        //      The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
        self.salt_enc = shared_secret.encrypt(&salt)?;
        //println!("{}", StrBuf::bufh("salt_enc", &self.salt_enc));

        // saltAuth: authenticate(shared secret, saltEnc)
        self.salt_auth = shared_secret.authenticate(&self.salt_enc)?;
        //println!("{}", StrBuf::bufh("salt_auth", &self.salt_auth));

        self.pin_protocol_version = shared_secret.pin_protocol_version();
        self.shared_secret = shared_secret;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
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
