/*!
## Examples

[-> Examples](https://github.com/gebogebogebo/ctap-hid-fido2/blob/master/README.md#examples)

*/

pub mod auth_data;
mod config_command;
mod cose;
mod credential_management;
mod credential_management_command;
pub mod credential_management_params;
mod credential_management_response;
mod ctapdef;
mod ctaphid;
mod ctapihd_nitro;
pub mod enc_aes256_cbc;
pub mod enc_hmac_sha_256;
mod get_assertion;
mod get_assertion_command;
pub mod get_assertion_params;
mod get_assertion_response;
mod get_next_assertion_command;
mod hmac;
pub mod nitrokey;
mod p256;
mod pintoken;
pub mod public_key;
pub mod public_key_credential_descriptor;
pub mod public_key_credential_rp_entity;
pub mod public_key_credential_user_entity;
mod selection_command;
mod ss;
pub mod str_buf;
pub mod util;
pub mod verifier;

use crate::get_assertion_params::Assertion;
use crate::get_assertion_params::Extension as Gext;
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use anyhow::{anyhow, Error, Result};
use util::should_uv;

pub mod fidokey;
pub use fidokey::FidoKeyHid;

mod hid;

pub type Key = HidParam;
pub type Cfg = LibCfg;

#[derive(Clone)]
pub struct LibCfg {
    pub hid_params: Vec<HidParam>,
    pub enable_log: bool,
    pub use_pre_bio_enrollment: bool,
    pub use_pre_credential_management: bool,
    pub keep_alive_msg: String,
}

impl LibCfg {
    pub fn init() -> Self {
        LibCfg {
            hid_params: HidParam::auto(),
            enable_log: false,
            use_pre_bio_enrollment: true,
            use_pre_credential_management: true,
            keep_alive_msg: "- Touch the sensor on the authenticator".to_string(),
        }
    }
}

/// HID device vendor ID , product ID
#[derive(Clone)]
pub enum HidParam {
    /// Specified when looking for any FIDO device of a certain kind
    VidPid {vid: u16, pid: u16},
    /// Specified when looking to open a specific device. This is non-ambiguous
    /// when multiple devices of the same kind are connected.
    Path(String),
}

/// Struct that contains information about found HID devices. Also
/// contains a HidParam which can be used to lookup the device
/// later.
#[derive(Clone)]
pub struct HidInfo {
    /// Product ID
    pub pid: u16,
    /// Vendor ID
    pub vid: u16,
    /// A string describing the device provided by the device
    pub product_string: String,
    /// A generic information string build by this crate
    pub info: String,
    /// An parameter structure to be used to open this device
    /// later. This is almost always HidParam::Path.
    pub param: HidParam,
}

impl HidParam {
    /// Generate HID parameters for FIDO key devices
    pub fn get() -> Vec<HidParam> {
        vec![
            HidParam::VidPid { vid: 0x1050, pid: 0x0402 },  // Yubikey 4/5 U2F
            HidParam::VidPid { vid: 0x1050, pid: 0x0407 },  // Yubikey 4/5 OTP+U2F+CCID
            HidParam::VidPid { vid: 0x1050, pid: 0x0120 },  // Yubikey Touch U2F
            HidParam::VidPid { vid: 0x096E, pid: 0x085D },  // Biopass
            HidParam::VidPid { vid: 0x096E, pid: 0x0866 },  // All in pass
            HidParam::VidPid { vid: 0x0483, pid: 0xA2CA },  // Solokey 
            HidParam::VidPid { vid: 0x096E, pid: 0x0858 },  // ePass FIDO(A4B)
            HidParam::VidPid { vid: 0x20a0, pid: 0x42b1 },  // Nitrokey FIDO2 2.0.0
            HidParam::VidPid { vid: 0x32a3, pid: 0x3201 },  // Idem Key
        ]
    }
    pub fn auto() -> Vec<HidParam> {
        vec![]
    }
}

/// check Platform
#[cfg(target_os = "windows")]
pub fn hello() {
    println!("Hello, I'm Windows!");
}

#[cfg(target_os = "linux")]
pub fn hello() {
    println!("Hello, I'm Linux!");
}

#[cfg(target_os = "macos")]
pub fn hello() {
    println!("hello, I'm MacOS.");
}

/// Get HID devices
pub fn get_hid_devices() -> Vec<HidInfo> {
    hid::get_hid_devices(None)
}

/// Get HID FIDO devices
pub fn get_fidokey_devices() -> Vec<HidInfo> {
    hid::get_hid_devices(Some(0xf1d0))
}

fn get_device(cfg: &LibCfg) -> Result<FidoKeyHid> {
    let device = if cfg.hid_params.len() > 0 {
        FidoKeyHid::new(&cfg.hid_params, cfg).map_err(Error::msg)?
    } else {
        let mut devs = get_fidokey_devices();
        if devs.is_empty() {
            return Err(anyhow!("FIDO device not found."));
        }

        let device = devs.pop().unwrap().param;

        let params = vec![device];
        FidoKeyHid::new(&params, cfg).map_err(Error::msg)?
    };
    Ok(device)
}

/// Lights the LED on the FIDO key
pub fn wink(cfg: &LibCfg) -> Result<()> {
    let device = get_device(cfg)?;
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;
    ctaphid::ctaphid_wink(&device, &cid).map_err(Error::msg)
}

/// Authentication command(with PIN , non Resident Key)
pub fn get_assertion(
    cfg: &LibCfg,
    rpid: &str,
    challenge: &[u8],
    credential_id: &[u8],
    pin: Option<&str>,
) -> Result<Assertion> {
    let device = get_device(cfg)?;

    let asss = get_assertion::get_assertion(
        &device,
        rpid,
        challenge,
        credential_id,
        pin,
        true,
        should_uv(pin),
        None,
    )?;
    Ok(asss[0].clone())
}

/// Authentication command(with PIN , non Resident Key , Extension)
pub fn get_assertion_with_extensios(
    cfg: &LibCfg,
    rpid: &str,
    challenge: &[u8],
    credential_id: &[u8],
    pin: Option<&str>,
    extensions: Option<&Vec<Gext>>,
) -> Result<Assertion> {
    let device = get_device(cfg)?;
    let asss = get_assertion::get_assertion(
        &device,
        rpid,
        challenge,
        credential_id,
        pin,
        true,
        should_uv(pin),
        extensions,
    )?;
    Ok(asss[0].clone())
}

/// Authentication command(with PIN , Resident Key)
pub fn get_assertions_rk(
    cfg: &LibCfg,
    rpid: &str,
    challenge: &[u8],
    pin: Option<&str>,
) -> Result<Vec<Assertion>> {
    let device = get_device(cfg)?;
    let dmy: [u8; 0] = [];
    get_assertion::get_assertion(
        &device,
        rpid,
        challenge,
        &dmy,
        pin,
        true,
        should_uv(pin),
        None,
    )
}

#[derive(Debug)]
pub struct GetAssertionArgs<'a> {
    rpid: String,
    challenge: Vec<u8>,
    pin: Option<&'a str>,
    credential_id: Option<Vec<u8>>,
    uv: Option<bool>,
    extensions: Option<Vec<Gext>>,
}
impl<'a> GetAssertionArgs<'a> {
    pub fn builder() -> GetAssertionArgsBuilder<'a> {
        GetAssertionArgsBuilder::default()
    }
}

#[derive(Default)]
pub struct GetAssertionArgsBuilder<'a> {
    rpid: String,
    challenge: Vec<u8>,
    pin: Option<&'a str>,
    credential_id: Option<Vec<u8>>,
    uv: Option<bool>,
    extensions: Option<Vec<Gext>>,
}
impl<'a> GetAssertionArgsBuilder<'a> {
    pub fn new(rpid: &str, challenge: &[u8]) -> GetAssertionArgsBuilder<'a> {
        let mut result = GetAssertionArgsBuilder::default();
        result.uv = Some(true);
        result.rpid = String::from(rpid);
        result.challenge = challenge.to_vec();
        result
    }

    pub fn pin(mut self, pin: &'a str) -> GetAssertionArgsBuilder<'a> {
        self.pin = Some(pin);
        //self.uv = Some(false);
        self.uv = None;
        self
    }

    pub fn without_pin_and_uv(mut self) -> GetAssertionArgsBuilder<'a> {
        self.pin = None;
        self.uv = None;
        self
    }

    pub fn extensions(mut self, extensions: &[Gext]) -> GetAssertionArgsBuilder<'a> {
        self.extensions = Some(extensions.to_vec());
        self
    }

    pub fn credential_id(mut self, credential_id: &[u8]) -> GetAssertionArgsBuilder<'a> {
        self.credential_id = Some(credential_id.to_vec());
        self
    }

    pub fn build(self) -> GetAssertionArgs<'a> {
        GetAssertionArgs {
            rpid: self.rpid,
            challenge: self.challenge,
            pin: self.pin,
            credential_id: self.credential_id,
            uv: self.uv,
            extensions: self.extensions,
        }
    }
}
pub fn get_assertion_with_args(cfg: &LibCfg, args: &GetAssertionArgs) -> Result<Vec<Assertion>> {
    let device = get_device(cfg)?;

    let credential_id = if args.credential_id.is_some() {
        args.credential_id.as_ref().unwrap().to_vec()
    } else {
        let dmy: [u8; 0] = [];
        dmy.to_vec()
    };

    let extensions = if args.extensions.is_some() {
        Some(args.extensions.as_ref().unwrap())
    } else {
        None
    };

    let asss = get_assertion::get_assertion(
        &device,
        &args.rpid,
        &args.challenge,
        &credential_id,
        args.pin,
        true,
        args.uv,
        extensions,
    )?;

    Ok(asss)
}

/// CredentialManagement - getCredsMetadata (CTAP 2.1-PRE)
pub fn credential_management_get_creds_metadata(
    cfg: &LibCfg,
    pin: Option<&str>,
) -> Result<credential_management_params::CredentialsCount> {
    let device = get_device(cfg)?;
    let meta = credential_management::credential_management(
        &device,
        pin,
        credential_management_command::SubCommand::GetCredsMetadata,
        None,
        None,
        None,
    )?;
    Ok(credential_management_params::CredentialsCount::new(&meta))
}

/// CredentialManagement - enumerateRPsBegin & enumerateRPsNext (CTAP 2.1-PRE)
pub fn credential_management_enumerate_rps(
    cfg: &LibCfg,
    pin: Option<&str>,
) -> Result<Vec<credential_management_params::Rp>> {
    let device = get_device(cfg)?;
    let mut datas: Vec<credential_management_params::Rp> = Vec::new();
    let data = credential_management::credential_management(
        &device,
        pin,
        credential_management_command::SubCommand::EnumerateRPsBegin,
        None,
        None,
        None,
    )?;
    if data.total_rps > 0 {
        datas.push(credential_management_params::Rp::new(&data));
        let roop_n = data.total_rps - 1;
        for _ in 0..roop_n {
            let data = credential_management::credential_management(
                &device,
                pin,
                credential_management_command::SubCommand::EnumerateRPsGetNextRp,
                None,
                None,
                None,
            )?;
            datas.push(credential_management_params::Rp::new(&data));
        }
    }
    Ok(datas)
}

/// CredentialManagement - enumerateCredentialsBegin & enumerateCredentialsNext (CTAP 2.1-PRE)
pub fn credential_management_enumerate_credentials(
    cfg: &LibCfg,
    pin: Option<&str>,
    rpid_hash: &[u8],
) -> Result<Vec<credential_management_params::Credential>> {
    let device = get_device(cfg)?;
    let mut datas: Vec<credential_management_params::Credential> = Vec::new();

    let data = credential_management::credential_management(
        &device,
        pin,
        credential_management_command::SubCommand::EnumerateCredentialsBegin,
        Some(rpid_hash.to_vec()),
        None,
        None,
    )?;
    datas.push(credential_management_params::Credential::new(&data));
    if data.total_credentials > 0 {
        let roop_n = data.total_credentials - 1;
        for _ in 0..roop_n {
            let data = credential_management::credential_management(
                &device,
                pin,
                credential_management_command::SubCommand::EnumerateCredentialsGetNextCredential,
                Some(rpid_hash.to_vec()),
                None,
                None,
            )?;
            datas.push(credential_management_params::Credential::new(&data));
        }
    }
    Ok(datas)
}

/// CredentialManagement - deleteCredential (CTAP 2.1-PRE)
pub fn credential_management_delete_credential(
    cfg: &LibCfg,
    pin: Option<&str>,
    pkcd: Option<PublicKeyCredentialDescriptor>,
) -> Result<()> {
    let device = get_device(cfg)?;
    credential_management::credential_management(
        &device,
        pin,
        credential_management_command::SubCommand::DeleteCredential,
        None,
        pkcd,
        None,
    )?;
    Ok(())
}

/// CredentialManagement - updateUserInformation (CTAP 2.1-PRE)
pub fn credential_management_update_user_information(
    cfg: &LibCfg,
    pin: Option<&str>,
    pkcd: Option<PublicKeyCredentialDescriptor>,
    pkcue: Option<public_key_credential_user_entity::PublicKeyCredentialUserEntity>,
) -> Result<()> {
    let device = get_device(cfg)?;
    credential_management::credential_management(
        &device,
        pin,
        credential_management_command::SubCommand::UpdateUserInformation,
        None,
        pkcd,
        pkcue,
    )?;
    Ok(())
}

/// Selection (CTAP 2.1)
pub fn selection(cfg: &LibCfg) -> Result<String> {
    let device = get_device(cfg)?;
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;
    let send_payload = selection_command::create_payload();
    let _response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload).map_err(Error::msg)?;
    Ok("".to_string())
}

/// Get Config (CTAP 2.1)
pub fn config(cfg: &LibCfg) -> Result<String> {
    let device = get_device(cfg)?;
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;
    let send_payload = config_command::create_payload_enable_enterprise_attestation();
    let _response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload).map_err(Error::msg)?;
    Ok("".to_string())
}

//
// test
//
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_pin_auth() {
        let out_bytes = hex::decode("1A81CD600A1F6CF4BE5260FE3257B241").unwrap();
        let client_data_hash =
            hex::decode("E61E2BD6C4612662960B159CD54CF8EFF1A998C89B3742519D11F85E0F5E7876")
                .unwrap();
        let check = "F0AC99D6AAD2E199AF9CF25F6568A6F5".to_string();
        let sig = enc_hmac_sha_256::authenticate(&out_bytes, &client_data_hash);
        let pin_auth = sig[0..16].to_vec();
        assert_eq!(check, hex::encode(pin_auth).to_uppercase());
    }

    #[test]
    fn test_hmac() {
        let key = b"this is key".to_vec();
        let message = b"this is message".to_vec();

        let sig = enc_hmac_sha_256::authenticate(&key, &message);

        let check = "1BCF27BDA4891AFA5F53CC027B8835564E35A8E3B631AA0F0563299296AD5909".to_string();
        assert_eq!(check, hex::encode(sig).to_uppercase());
    }
}
