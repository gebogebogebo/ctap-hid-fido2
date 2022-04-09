/*!
## Examples

[-> Examples](https://github.com/gebogebogebo/ctap-hid-fido2/blob/master/README.md#examples)

*/

pub mod auth_data;
mod ctapdef;
mod ctaphid;
mod encrypt {
    pub mod cose;
    pub mod enc_aes256_cbc;
    pub mod enc_hmac_sha_256;
    pub mod p256;
    pub mod shared_secret;
}
mod hmac_ext;
mod pintoken;
pub mod public_key;
pub mod public_key_credential_descriptor;
pub mod public_key_credential_rp_entity;
pub mod public_key_credential_user_entity;
pub mod str_buf;
pub mod util;
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
    pub keep_alive_msg: String,
}

impl LibCfg {
    pub fn init() -> Self {
        LibCfg {
            enable_log: false,
            use_pre_bio_enrollment: true,
            use_pre_credential_management: true,
            keep_alive_msg: "- Touch the sensor on the authenticator".to_string(),
        }
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
    use ring::digest;
    use std::convert::TryFrom;
    use str_buf::StrBuf;

    #[test]
    fn test_create_pin_auth() {
        let out_bytes = hex::decode("1A81CD600A1F6CF4BE5260FE3257B241").unwrap();
        let client_data_hash =
            hex::decode("E61E2BD6C4612662960B159CD54CF8EFF1A998C89B3742519D11F85E0F5E7876")
                .unwrap();
        let check = "F0AC99D6AAD2E199AF9CF25F6568A6F5".to_string();
        let sig = encrypt::enc_hmac_sha_256::authenticate(&out_bytes, &client_data_hash);
        let pin_auth = sig[0..16].to_vec();
        assert_eq!(check, hex::encode(pin_auth).to_uppercase());
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
        let hasher = digest::digest(&digest::SHA256, &key_str.as_bytes());
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
        let hasher = digest::digest(&digest::SHA256, &key_str.as_bytes());
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
