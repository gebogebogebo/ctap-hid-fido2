/*!
## Examples

[-> Examples](https://github.com/gebogebogebo/ctap-hid-fido2/blob/master/README.md#examples)

*/

pub mod auth_data;
mod bio_enrollment;
mod bio_enrollment_command;
pub mod bio_enrollment_params;
mod bio_enrollment_response;
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
mod make_credential;
mod make_credential_command;
pub mod make_credential_params;
mod make_credential_response;
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

//
use crate::bio_enrollment_command::SubCommand as BioCmd;
use crate::bio_enrollment_params::{BioSensorInfo, EnrollStatus1, EnrollStatus2, TemplateInfo};
use crate::get_assertion_params::Assertion;
use crate::get_assertion_params::Extension as Gext;
use crate::make_credential_params::Attestation;
use crate::make_credential_params::CredentialSupportedKeyType;
use crate::make_credential_params::Extension as Mext;
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use anyhow::{anyhow, Error, Result};

mod fidokey;
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

/// Specification for a HID device to connect to
#[derive(Clone)]
pub enum HidParam {
    /// Specified when looking for any FIDO device of a certain kind
    /// (Ambiguous when multiple of the same device connected)
    VidPid {vid: u16, pid: u16},
    /// Specified when looking for a specific device (non-ambiguous when
    /// multiple of the same device connected)
    Path(String),
}

/// Struct that contains information about found HID devices. Also
/// contains a HidParam which can be used to lookup the device
/// later.
#[derive(Clone)]
pub struct HidInfo {
    pub pid: u16,
    pub vid: u16,
    pub product_string: String,
    pub info: String,
    pub param: HidParam,
}


impl HidParam {
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

/// Registration command.Generate credentials(with PIN,non Resident Key)
pub fn make_credential(
    cfg: &LibCfg,
    rpid: &str,
    challenge: &[u8],
    pin: Option<&str>,
) -> Result<Attestation> {
    let device = get_device(cfg)?;
    make_credential::make_credential(&device, rpid, challenge, pin, false, None, None, None)
}

/// Registration command. Generate credentials (with PIN, non Resident Key) while also
/// specifying the type of key you'd like to create.
pub fn make_credential_with_key_type(
    cfg: &LibCfg,
    rpid: &str,
    challenge: &[u8],
    pin: Option<&str>,
    key_type: Option<CredentialSupportedKeyType>,
) -> Result<Attestation> {
    let device = get_device(cfg)?;
    make_credential::make_credential(&device, rpid, challenge, pin, false, None, None, key_type)
}

pub fn make_credential_with_extensions(
    cfg: &LibCfg,
    rpid: &str,
    challenge: &[u8],
    pin: Option<&str>,
    extensions: Option<&Vec<Mext>>,
) -> Result<Attestation> {
    let device = get_device(cfg)?;
    make_credential::make_credential(&device, rpid, challenge, pin, false, None, extensions, None)
}

/// Registration command.Generate credentials(with PIN ,Resident Key)
pub fn make_credential_rk(
    cfg: &LibCfg,
    rpid: &str,
    challenge: &[u8],
    pin: Option<&str>,
    rkparam: &PublicKeyCredentialUserEntity,
) -> Result<Attestation> {
    let device = get_device(cfg)?;
    make_credential::make_credential(
        &device,
        rpid,
        challenge,
        pin,
        true,
        Some(rkparam),
        //None,
        None,
        None,
    )
}

/// Registration command.Generate credentials(without PIN ,non Resident Key)
pub fn make_credential_without_pin(
    cfg: &LibCfg,
    rpid: &str,
    challenge: &[u8],
) -> Result<Attestation> {
    let device = get_device(cfg)?;
    make_credential::make_credential(&device, rpid, challenge, None, false, None, None, None)
}

pub fn make_credential_with_args(cfg: &LibCfg, args: &MakeCredentialArgs) -> Result<Attestation> {
    let device = get_device(cfg)?;

    let extensions = if args.extensions.is_some() {
        Some(args.extensions.as_ref().unwrap())
    } else {
        None
    };

    let (rk, rk_param) = if args.rkparam.is_some() {
        (true, Some(args.rkparam.as_ref().unwrap()))
    } else {
        (false, None)
    };

    make_credential::make_credential(
        &device,
        &args.rpid,
        &args.challenge,
        args.pin,
        rk,
        rk_param,
        extensions,
        args.key_type,
    )
}

#[derive(Debug)]
pub struct MakeCredentialArgs<'a> {
    rpid: String,
    challenge: Vec<u8>,
    pin: Option<&'a str>,
    key_type: Option<CredentialSupportedKeyType>,
    extensions: Option<Vec<Mext>>,
    rkparam: Option<PublicKeyCredentialUserEntity>,
}
impl<'a> MakeCredentialArgs<'a> {
    pub fn builder() -> MakeCredentialArgsBuilder<'a> {
        MakeCredentialArgsBuilder::default()
    }
}

#[derive(Default)]
pub struct MakeCredentialArgsBuilder<'a> {
    rpid: String,
    challenge: Vec<u8>,
    pin: Option<&'a str>,
    key_type: Option<CredentialSupportedKeyType>,
    extensions: Option<Vec<Mext>>,
    rkparam: Option<PublicKeyCredentialUserEntity>,
}
impl<'a> MakeCredentialArgsBuilder<'a> {
    pub fn new(rpid: &str, challenge: &[u8]) -> MakeCredentialArgsBuilder<'a> {
        let mut result = MakeCredentialArgsBuilder::default();
        result.rpid = String::from(rpid);
        result.challenge = challenge.to_vec();
        result
    }

    pub fn pin(mut self, pin: &'a str) -> MakeCredentialArgsBuilder {
        self.pin = Some(pin);
        self
    }

    pub fn key_type(
        mut self,
        key_type: CredentialSupportedKeyType,
    ) -> MakeCredentialArgsBuilder<'a> {
        self.key_type = Some(key_type);
        self
    }

    pub fn extensions(mut self, extensions: &[Mext]) -> MakeCredentialArgsBuilder<'a> {
        self.extensions = Some(extensions.to_vec());
        self
    }

    pub fn rkparam(
        mut self,
        rkparam: &PublicKeyCredentialUserEntity,
    ) -> MakeCredentialArgsBuilder<'a> {
        self.rkparam = Some(rkparam.clone());
        self
    }

    pub fn build(self) -> MakeCredentialArgs<'a> {
        MakeCredentialArgs {
            rpid: self.rpid,
            challenge: self.challenge,
            pin: self.pin,
            key_type: self.key_type,
            extensions: self.extensions,
            rkparam: self.rkparam,
        }
    }
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

    let asss =
        get_assertion::get_assertion(&device, rpid, challenge, credential_id, pin, true, None)?;
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
        //None,
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
    get_assertion::get_assertion(&device, rpid, challenge, &dmy, pin, true, None)
}

#[derive(Debug)]
pub struct GetAssertionArgs<'a> {
    rpid: String,
    challenge: Vec<u8>,
    pin: Option<&'a str>,
    credential_id: Option<Vec<u8>>,
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
    extensions: Option<Vec<Gext>>,
}
impl<'a> GetAssertionArgsBuilder<'a> {
    pub fn new(rpid: &str, challenge: &[u8]) -> GetAssertionArgsBuilder<'a> {
        let mut result = GetAssertionArgsBuilder::default();
        result.rpid = String::from(rpid);
        result.challenge = challenge.to_vec();
        result
    }

    pub fn pin(mut self, pin: &'a str) -> GetAssertionArgsBuilder {
        self.pin = Some(pin);
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
        extensions,
    )?;

    Ok(asss)
}

/// BioEnrollment - getFingerprintSensorInfo (CTAP 2.1-PRE)
pub fn bio_enrollment_get_fingerprint_sensor_info(cfg: &LibCfg) -> Result<BioSensorInfo> {
    let device = get_device(cfg)?;
    let init = bio_enrollment::bio_enrollment_init(&device, None).map_err(Error::msg)?;

    // 6.7.2. Get bio modality
    let data1 = bio_enrollment::bio_enrollment(&device, &init.0, None, None, None, None)
        .map_err(Error::msg)?;
    if cfg.enable_log {
        println!("{}", data1);
    }

    // 6.7.3. Get fingerprint sensor info
    let data2 = bio_enrollment::bio_enrollment(
        &device,
        &init.0,
        None,
        Some(BioCmd::GetFingerprintSensorInfo),
        None,
        None,
    )
    .map_err(Error::msg)?;

    if cfg.enable_log {
        println!("{}", data2);
    }

    Ok(BioSensorInfo {
        modality: data1.modality.into(),
        fingerprint_kind: data2.fingerprint_kind.into(),
        max_capture_samples_required_for_enroll: data2.max_capture_samples_required_for_enroll,
        max_template_friendly_name: data2.max_template_friendly_name,
    })
}

/// BioEnrollment - EnrollBegin
pub fn bio_enrollment_begin(
    cfg: &LibCfg,
    pin: &str,
    timeout_milliseconds: Option<u16>,
) -> Result<(EnrollStatus1, EnrollStatus2)> {
    let device = get_device(cfg)?;
    let init = bio_enrollment::bio_enrollment_init(&device, Some(pin))?;

    let data = bio_enrollment::bio_enrollment(
        &device,
        &init.0,
        init.1.as_ref(),
        Some(BioCmd::EnrollBegin),
        None,
        timeout_milliseconds,
    )?;
    if cfg.enable_log {
        println!("{}", data);
    }
    let result1 = EnrollStatus1 {
        device: device,
        cid: init.0,
        pin_token: init.1,
        template_id: data.template_id.to_vec(),
    };
    let finish = data.last_enroll_sample_status == 0x00 && data.remaining_samples == 0;
    let result2 = EnrollStatus2 {
        status: data.last_enroll_sample_status as u8,
        message: ctapdef::get_ctap_last_enroll_sample_status_message(
            data.last_enroll_sample_status as u8,
        ),
        remaining_samples: data.remaining_samples,
        is_finish: finish,
    };
    Ok((result1, result2))
}

/// BioEnrollment - CaptureNext
pub fn bio_enrollment_next(
    cfg: &LibCfg,
    enroll_status: &EnrollStatus1,
    timeout_milliseconds: Option<u16>,
) -> Result<EnrollStatus2> {
    let template_info = TemplateInfo::new(&enroll_status.template_id, None);
    let data = bio_enrollment::bio_enrollment(
        &enroll_status.device,
        &enroll_status.cid,
        enroll_status.pin_token.as_ref(),
        Some(BioCmd::EnrollCaptureNextSample),
        Some(template_info),
        timeout_milliseconds,
    )?;
    if cfg.enable_log {
        println!("{}", data);
    }
    let finish = data.last_enroll_sample_status == 0x00 && data.remaining_samples == 0;
    let result = EnrollStatus2 {
        status: data.last_enroll_sample_status as u8,
        message: ctapdef::get_ctap_last_enroll_sample_status_message(
            data.last_enroll_sample_status as u8,
        ),
        remaining_samples: data.remaining_samples,
        is_finish: finish,
    };
    Ok(result)
}

/// BioEnrollment - Cancel current enrollment
pub fn bio_enrollment_cancel(cfg: &LibCfg, enroll_status: &EnrollStatus1) -> Result<()> {
    let data = bio_enrollment::bio_enrollment(
        &enroll_status.device,
        &enroll_status.cid,
        enroll_status.pin_token.as_ref(),
        Some(BioCmd::CancelCurrentEnrollment),
        None,
        None,
    )?;
    if cfg.enable_log {
        println!("{}", data);
    }
    Ok(())
}

/// BioEnrollment - enumerateEnrollments (CTAP 2.1-PRE)
/// 6.7.6. Enumerate enrollments
pub fn bio_enrollment_enumerate_enrollments(cfg: &LibCfg, pin: &str) -> Result<Vec<TemplateInfo>> {
    let device = get_device(cfg)?;
    let init = bio_enrollment::bio_enrollment_init(&device, Some(pin))?;
    let pin_token = init.1.unwrap();

    let data = bio_enrollment::bio_enrollment(
        &device,
        &init.0,
        Some(&pin_token),
        Some(BioCmd::EnumerateEnrollments),
        None,
        None,
    )?;
    if cfg.enable_log {
        println!("{}", data);
    }

    Ok(data.template_infos)
}

/// BioEnrollment - Rename/Set FriendlyName
/// 6.7.7. Rename/Set FriendlyName
pub fn bio_enrollment_set_friendly_name(
    cfg: &LibCfg,
    pin: &str,
    template_id: &[u8],
    template_name: &str,
) -> Result<()> {
    let template_info = TemplateInfo::new(template_id, Some(template_name));

    let device = get_device(cfg)?;
    let init = bio_enrollment::bio_enrollment_init(&device, Some(pin))?;
    let pin_token = init.1.unwrap();

    let data = bio_enrollment::bio_enrollment(
        &device,
        &init.0,
        Some(&pin_token),
        Some(BioCmd::SetFriendlyName),
        Some(template_info),
        None,
    )?;
    if cfg.enable_log {
        println!("{}", data);
    }
    Ok(())
}

/// 6.7.8. Remove enrollment
pub fn bio_enrollment_remove(cfg: &LibCfg, pin: &str, template_id: &[u8]) -> Result<()> {
    let device = get_device(cfg)?;
    let init = bio_enrollment::bio_enrollment_init(&device, Some(pin))?;
    let pin_token = init.1.unwrap();

    let template_info = TemplateInfo::new(template_id, None);
    let data = bio_enrollment::bio_enrollment(
        &device,
        &init.0,
        Some(&pin_token),
        Some(BioCmd::RemoveEnrollment),
        Some(template_info),
        None,
    )?;
    if cfg.enable_log {
        println!("{}", data);
    }
    Ok(())
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

/// Selection (CTAP 2.1-PRE)
pub fn selection(cfg: &LibCfg) -> Result<String> {
    let device = get_device(cfg)?;
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;
    let send_payload = selection_command::create_payload();
    let _response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload).map_err(Error::msg)?;
    Ok("".to_string())
}

/// Get Config (CTAP 2.1-PRE)
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
    fn test_make_credential_with_pin_non_rk_command() {
        let rpid = "test.com";
        let challenge = b"this is challenge".to_vec();
        // create windows
        let pin_auth = hex::decode("6F79FB322D74972ACAA844C10C183BF7").unwrap();
        let check = "01A7015820E61E2BD6C4612662960B159CD54CF8EFF1A998C89B3742519D11F85E0F5E787602A262696468746573742E636F6D646E616D656003A36269644100646E616D6561206B646973706C61794E616D6561200481A263616C672664747970656A7075626C69632D6B657907A162726BF408506F79FB322D74972ACAA844C10C183BF70901".to_string();

        // create cmmand
        let send_payload = {
            let mut params =
                make_credential_command::Params::new(rpid, challenge.to_vec(), [].to_vec());
            params.option_rk = false; // non rk
                                      //params.option_uv = true;

            println!(
                "- client_data_hash({:02})    = {:?}",
                params.client_data_hash.len(),
                util::to_hex_str(&params.client_data_hash)
            );

            params.pin_auth = pin_auth.to_vec();

            make_credential_command::create_payload(params, None)
        };

        //println!(
        //    "- make_credential({:02})    = {:?}",
        //    send_payload.len(),
        //    util::to_hex_str(&send_payload)
        //);

        let command = hex::encode(send_payload).to_uppercase();
        assert_eq!(command, check);
    }

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
