use crate::crypto::hmac;
use anyhow::{anyhow, Result};

pub fn authenticate(key: &[u8], message: &[u8]) -> Vec<u8> {
    let hmac_key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&hmac_key, message);
    tag.as_ref().to_vec()
}

/// Compute a pinUvAuthParam for the negotiated PIN/UV Auth Protocol version.
///
/// - Protocol One (6.5.7. authenticate): LEFT(HMAC-SHA-256(key, message), 16)
/// - Protocol Two (6.5.8. authenticate): HMAC-SHA-256(key, message) (32 bytes, untruncated)
pub fn compute_pin_uv_auth_param(
    key: &[u8],
    message: &[u8],
    pin_protocol_version: u8,
) -> Result<Vec<u8>> {
    let sig = authenticate(key, message);
    match pin_protocol_version {
        1 => Ok(sig[0..16].to_vec()),
        2 => Ok(sig),
        _ => Err(anyhow!("unknown pin_protocol_version")),
    }
}
