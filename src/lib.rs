/*!
## Examples

[-> Examples](https://github.com/gebogebogebo/ctap-hid-fido2/blob/master/README.md#examples)

*/

pub mod auth_data;
mod crypto;
mod ctapdef;
mod ctaphid;
mod encrypt {
    pub mod cose;
    pub mod enc_aes256_cbc;
    pub mod enc_hmac_sha_256;
    pub mod p256;
    pub mod shared_secret;
    pub mod shared_secret2;
}
mod hmac_ext;
mod pin_uv_auth_protocol;
mod pintoken;
pub mod public_key;
pub mod public_key_credential_descriptor;
pub mod public_key_credential_rp_entity;
pub mod public_key_credential_user_entity;
pub mod str_buf;
pub mod util;
pub mod util_ciborium;
pub mod verifier;

use anyhow::{anyhow, Result};

pub mod fidokey;
pub use fidokey::FidoKeyHid;

mod hid;
pub use hid::{HidInfo, HidParam};

pub type Cfg = LibCfg;

#[derive(Clone)]
pub struct LibCfg {
    pub enable_log: bool,
    pub use_pre_bio_enrollment: bool,
    pub use_pre_credential_management: bool,
    pub enable_keep_alive_msg: bool,
    pub keep_alive_msg: String,
    pub keep_alive_msg_to_stderr: bool,
}

impl LibCfg {
    pub fn init() -> Self {
        LibCfg {
            // Print CTAP/HID debug traces (hex dumps, etc.) to stdout when true.
            enable_log: false,
            // Use pre-FIDO 2.1 bio enrollment command variants when true.
            use_pre_bio_enrollment: true,
            // Use pre-FIDO 2.1 credential management command variants when true.
            use_pre_credential_management: true,
            // Print a user-facing message while waiting on CTAPHID_KEEPALIVE (user presence).
            enable_keep_alive_msg: true,
            // Text shown for keep-alive; empty string disables output even if enable_keep_alive_msg is true.
            keep_alive_msg: "- Touch the sensor on the authenticator".to_string(),
            // When true, keep_alive_msg goes to stderr; when false, to stdout.
            keep_alive_msg_to_stderr: false,
        }
    }

    pub fn with_enable_log(mut self, enable: bool) -> Self {
        self.enable_log = enable;
        self
    }

    pub fn with_keep_alive_msg_to_stderr(mut self, to_stderr: bool) -> Self {
        self.keep_alive_msg_to_stderr = to_stderr;
        self
    }
}

/// Get HID devices
pub fn get_hid_devices() -> Vec<HidInfo> {
    hid::get_hid_devices(None)
}

/// Get HID FIDO devices
pub fn get_fidokey_devices() -> Vec<HidInfo> {
    hid::get_hid_devices(Some(0xf1d0))
}

/// Simple factory to create FidoKeyHid
pub struct FidoKeyHidFactory {}

impl FidoKeyHidFactory {
    pub fn create(cfg: &LibCfg) -> Result<FidoKeyHid> {
        let device = {
            let mut devs = get_fidokey_devices();
            if devs.is_empty() {
                return Err(anyhow!("FIDO device not found."));
            }
            if devs.len() > 1 {
                return Err(anyhow!("Multiple FIDO devices found."));
            }

            let device = devs.pop().unwrap().param;

            let params = vec![device];
            FidoKeyHid::new(&params, cfg)?
        };
        Ok(device)
    }

    pub fn create_by_params(params: &[HidParam], cfg: &LibCfg) -> Result<FidoKeyHid> {
        FidoKeyHid::new(params, cfg)
    }
}

//
// test
//
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::digest;
    use std::convert::TryFrom;
    use str_buf::StrBuf;

    #[test]
    fn test_create_pin_auth_protocol_one() {
        // PIN/UV Auth Protocol One truncates the HMAC-SHA-256 output to 16 bytes
        // (CTAP 2.2 6.5.7. authenticate(key, message)).
        let out_bytes = hex::decode("1A81CD600A1F6CF4BE5260FE3257B241").unwrap();
        let client_data_hash =
            hex::decode("E61E2BD6C4612662960B159CD54CF8EFF1A998C89B3742519D11F85E0F5E7876")
                .unwrap();
        let check = "F0AC99D6AAD2E199AF9CF25F6568A6F5".to_string();
        let pin_auth =
            pin_uv_auth_protocol::compute_pin_uv_auth_param(&out_bytes, &client_data_hash, 1)
                .unwrap();
        assert_eq!(pin_auth.len(), 16);
        assert_eq!(check, hex::encode(pin_auth).to_uppercase());
    }

    #[test]
    fn test_create_pin_auth_protocol_two() {
        // PIN/UV Auth Protocol Two returns the full 32-byte HMAC-SHA-256 output
        // without truncation (CTAP 2.2 6.5.8. authenticate(key, message)).
        let out_bytes = hex::decode("1A81CD600A1F6CF4BE5260FE3257B241").unwrap();
        let client_data_hash =
            hex::decode("E61E2BD6C4612662960B159CD54CF8EFF1A998C89B3742519D11F85E0F5E7876")
                .unwrap();
        let check =
            "F0AC99D6AAD2E199AF9CF25F6568A6F555D6394CDC35D81573D71A3B3CB275F3".to_string();
        let pin_auth =
            pin_uv_auth_protocol::compute_pin_uv_auth_param(&out_bytes, &client_data_hash, 2)
                .unwrap();
        assert_eq!(pin_auth.len(), 32);
        assert_eq!(check, hex::encode(pin_auth).to_uppercase());
    }

    #[test]
    fn test_create_pin_auth_unknown_protocol() {
        let out_bytes = hex::decode("1A81CD600A1F6CF4BE5260FE3257B241").unwrap();
        let client_data_hash =
            hex::decode("E61E2BD6C4612662960B159CD54CF8EFF1A998C89B3742519D11F85E0F5E7876")
                .unwrap();
        let result =
            pin_uv_auth_protocol::compute_pin_uv_auth_param(&out_bytes, &client_data_hash, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_hmac() {
        let key = b"this is key".to_vec();
        let message = b"this is message".to_vec();

        let sig = encrypt::enc_hmac_sha_256::authenticate(&key, &message);

        let check = "1BCF27BDA4891AFA5F53CC027B8835564E35A8E3B631AA0F0563299296AD5909".to_string();
        assert_eq!(check, hex::encode(sig).to_uppercase());
    }

    #[test]
    fn test_enc_hmac_sha_256() {
        let key_str = "this is key.";
        let hasher = digest::digest(&digest::SHA256, key_str.as_bytes());
        let key = <[u8; 32]>::try_from(hasher.as_ref()).unwrap();

        let message = "this is message.";
        let sig = encrypt::enc_hmac_sha_256::authenticate(&key, message.as_bytes());
        print!("{}", StrBuf::bufh("- hmac signature", &sig));
        assert_eq!(
            sig,
            util::to_str_hex("BF3D3FCFC4462CDCBEBBBC8AF82EA38B7B5ED4259B2061322C57B5CA696D6080")
        );
    }

    #[test]
    fn test_enc_aes256_cbc() {
        let key_str = "this is key.";
        let hasher = digest::digest(&digest::SHA256, key_str.as_bytes());
        let key = <[u8; 32]>::try_from(hasher.as_ref()).unwrap();

        let message = "this is message.";
        let enc_data = encrypt::enc_aes256_cbc::encrypt_message_str(&key, message);
        print!("{}", StrBuf::bufh("- enc_data", &enc_data));
        assert_eq!(
            enc_data,
            util::to_str_hex("37455A8392187439EFAA249617AAB5C2")
        );

        let dec_data = encrypt::enc_aes256_cbc::decrypt_message_str(&key, &enc_data);
        print!("- dec_data = {}", dec_data);
        assert_eq!(dec_data, message);
    }
}
