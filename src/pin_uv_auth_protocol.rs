use crate::encrypt::enc_hmac_sha_256;
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
