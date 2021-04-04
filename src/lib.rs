/*!
## Examples

[-> Examples](https://github.com/gebogebogebo/ctap-hid-fido2/blob/master/README.md#examples)

*/

mod client_pin;
mod client_pin_command;
mod client_pin_response;
mod config_command;
mod cose;
mod credential_management;
mod credential_management_command;
pub mod credential_management_params;
mod credential_management_response;
mod ctapdef;
mod ctaphid;
mod ctapihd_nitro;
mod get_assertion;
mod get_assertion_command;
pub mod get_assertion_params;
mod get_assertion_response;
mod get_info;
mod get_info_command;
mod get_info_response;
mod get_next_assertion_command;
mod make_credential;
mod make_credential_command;
pub mod make_credential_params;
mod make_credential_response;
pub mod nitrokey;
mod p256;
mod pintoken;
mod selection_command;
mod ss;
pub mod util;
pub mod verifier;

#[cfg(not(target_os = "linux"))]
mod fidokey;

// for pi
#[cfg(target_os = "linux")]
mod fidokey_pi;

#[cfg(target_os = "linux")]
mod hid_common;
#[cfg(target_os = "linux")]
mod hid_linux;

#[cfg(not(target_os = "linux"))]
use crate::fidokey::*;

// for pi
#[cfg(target_os = "linux")]
use crate::fidokey_pi::*;

/// HID device vendor ID , product ID
pub struct HidParam {
    /// vendor ID
    pub vid: u16,
    /// product ID
    pub pid: u16,
}

impl HidParam {
    /// Generate HID parameters for FIDO key devices
    /// - yubikey 4/5 u2f = vid:0x1050 , pid:0x0402
    /// - yubikey 4/5 otp+u2f+ccid = vid:0x1050, pid:0x0407
    /// - yubikey touch u2f = vid:0x1050 , pid:0x0120
    /// - biopass = vid:0x096E , pid:0x085D
    /// - all in pass = vid:0x096E , pid:0x0866
    /// - solokey = vid:0x0483 , pid:0xa2ca
    /// - Nitrokey = vid:0x20a0 , pid:0x42b1
    pub fn get_default_params() -> Vec<HidParam> {
        vec![
            HidParam {
                vid: 0x1050,
                pid: 0x0402,
            }, // yubikey 4/5 u2f
            HidParam {
                vid: 0x1050,
                pid: 0x0407,
            }, // yubikey 4/5 otp+u2f+ccid
            HidParam {
                vid: 0x1050,
                pid: 0x0120,
            }, // yubikey touch u2f
            HidParam {
                vid: 0x096E,
                pid: 0x085D,
            }, // biopass
            HidParam {
                vid: 0x096E,
                pid: 0x0866,
            }, // all in pass
            HidParam {
                vid: 0x0483,
                pid: 0xa2ca,
            }, // solokey
            HidParam {
                vid: 0x096e,
                pid: 0x0858,
            }, // ePass FIDO(A4B)
            HidParam {
                vid: 0x20a0,
                pid: 0x42b1,
            }, // Nitrokey FIDO2 2.0.0
        ]
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
pub fn get_hid_devices() -> Vec<(String, HidParam)> {
    FidoKeyHid::get_hid_devices(None)
}

/// Get HID FIDO devices
pub fn get_fidokey_devices() -> Vec<(String, HidParam)> {
    FidoKeyHid::get_hid_devices(Some(0xf1d0))
}

/// Lights the LED on the FIDO key
pub fn wink(hid_params: &[HidParam]) -> Result<(), String> {
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;
    ctaphid::ctaphid_wink(&device, &cid)
}

/// Get FIDO key information
pub fn get_info(hid_params: &[HidParam]) -> Result<Vec<(String, String)>, String> {
    get_info::get_info(hid_params)
}

/// Get FIDO key information (CTAP 1.0)
pub fn get_info_u2f(hid_params: &[HidParam]) -> Result<String, String> {
    get_info::get_info_u2f(hid_params)
}

/// Get PIN retry count
pub fn get_pin_retries(hid_params: &[HidParam]) -> Result<i32, String> {
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;

    let send_payload =
        client_pin_command::create_payload(client_pin_command::SubCommand::GetRetries)?;
    //println!("{}",util::to_hex_str(&send_payload));

    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;

    let pin = client_pin_response::parse_cbor_client_pin_get_retries(&response_cbor)?;
    //println!("authenticatorClientPIN (0x06) - getRetries");
    //println!("- retries       = {:?}", pin.retries);

    Ok(pin.retries)
}

/// Registration command.Generate credentials(with PIN,non Resident Key)
pub fn make_credential(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    pin: Option<&str>,
) -> Result<make_credential_params::Attestation, String> {
    make_credential::make_credential(hid_params, rpid, challenge, pin, false, None)
}

/// Registration command.Generate credentials(with PIN ,Resident Key)
pub fn make_credential_rk(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    pin: Option<&str>,
    rkparam: &make_credential_params::RkParam,
) -> Result<make_credential_params::Attestation, String> {
    make_credential::make_credential(hid_params, rpid, challenge, pin, true, Some(rkparam))
}

/// Registration command.Generate credentials(without PIN ,non Resident Key)
pub fn make_credential_without_pin(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
) -> Result<make_credential_params::Attestation, String> {
    make_credential::make_credential(hid_params, rpid, challenge, None, false, None)
}

/// Authentication command(with PIN , non Resident Key)
pub fn get_assertion(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    credential_id: &[u8],
    pin: Option<&str>,
) -> Result<get_assertion_params::Assertion, String> {
    let asss = get_assertion::get_assertion(hid_params, rpid, challenge, credential_id, pin, true)?;
    Ok(asss[0].clone())
}

/// Authentication command(with PIN , Resident Key)
pub fn get_assertions_rk(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    pin: Option<&str>,
) -> Result<Vec<get_assertion_params::Assertion>, String> {
    let dmy: [u8; 0] = [];
    get_assertion::get_assertion(hid_params, rpid, challenge, &dmy, pin, true)
}

/// CredentialManagement - getCredsMetadata
pub fn credential_management_get_creds_metadata(
    hid_params: &[HidParam],
    pin: Option<&str>,
) -> Result<credential_management_params::CredentialsCount, String> {
    let meta = credential_management::credential_management(
        hid_params,
        pin,
        credential_management_command::SubCommand::GetCredsMetadata,
        None,
        None,
        None,
    )?;
    Ok(credential_management_params::CredentialsCount::new(meta))
}

/// CredentialManagement - enumerateRPsBegin & enumerateRPsNext
pub fn credential_management_enumerate_rps(
    hid_params: &[HidParam],
    pin: Option<&str>,
) -> Result<Vec<credential_management_params::CredsMetadata>, String> {
    let mut datas: Vec<credential_management_params::CredsMetadata> = Vec::new();
    let data = credential_management::credential_management(
        hid_params,
        pin,
        credential_management_command::SubCommand::EnumerateRPsBegin,
        None,
        None,
        None,
    )?;
    datas.push(data.clone());
    if data.total_rps > 0 {
        let roop_n = data.total_rps - 1;
        for _ in 0..roop_n {
            let data = credential_management::credential_management(
                hid_params,
                pin,
                credential_management_command::SubCommand::EnumerateRPsGetNextRP,
                None,
                None,
                None,
            )?;
            datas.push(data);
        }
    }
    Ok(datas)
}

/// CredentialManagement - enumerateCredentialsBegin & enumerateCredentialsNext
pub fn credential_management_enumerate_credentials(
    hid_params: &[HidParam],
    pin: Option<&str>,
    rpid_hash: Vec<u8>,
) -> Result<Vec<credential_management_params::CredsMetadata>, String> {
    let data = credential_management::credential_management(
        hid_params,
        pin,
        credential_management_command::SubCommand::EnumerateCredentialsBegin,
        Some(rpid_hash.to_vec()),
        None,
        None,
    )?;
    let mut datas: Vec<credential_management_params::CredsMetadata> = Vec::new();
    datas.push(data.clone());
    if data.total_credentials > 0 {
        let roop_n = data.total_credentials - 1;
        for _ in 0..roop_n {
            let data = credential_management::credential_management(
                hid_params,
                pin,
                credential_management_command::SubCommand::EnumerateCredentialsGetNextCredential,
                Some(rpid_hash.to_vec()),
                None,
                None,
            )?;
            datas.push(data);
        }
    }
    Ok(datas)
}

/// CredentialManagement - deleteCredential
pub fn credential_management_delete_credential(
    hid_params: &[HidParam],
    pin: Option<&str>,
    pkcd: Option<credential_management_params::PublicKeyCredentialDescriptor>,
) -> Result<credential_management_params::CredsMetadata, String> {
    credential_management::credential_management(
        hid_params,
        pin,
        credential_management_command::SubCommand::DeleteCredential,
        None,
        pkcd,
        None,
    )
}

/// CredentialManagement - updateUserInformation
pub fn credential_management_update_user_information(
    hid_params: &[HidParam],
    pin: Option<&str>,
    pkcd: Option<credential_management_params::PublicKeyCredentialDescriptor>,
    pkcue: Option<credential_management_params::PublicKeyCredentialUserEntity>,
) -> Result<credential_management_params::CredsMetadata, String> {
    credential_management::credential_management(
        hid_params,
        pin,
        credential_management_command::SubCommand::UpdateUserInformation,
        None,
        pkcd,
        pkcue,
    )
}

/// Selection
pub fn selection(hid_params: &[HidParam]) -> Result<String, String> {
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;

    let send_payload = selection_command::create_payload();
    println!("{}", util::to_hex_str(&send_payload));

    let _response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;

    Ok("".to_string())
}

/// Get Config
pub fn config(hid_params: &[HidParam]) -> Result<String, String> {
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;

    let send_payload = config_command::create_payload_enable_enterprise_attestation();
    println!("{}", util::to_hex_str(&send_payload));

    let _response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;

    Ok("".to_string())
}

//
// test
//
#[cfg(test)]
mod tests {
    use super::*;
    //use serde_cbor::Value;
    //use num::NumCast;
    use ring::{digest, hmac};

    #[test]
    fn test_client_pin_get_keyagreement() {
        let hid_params = HidParam::get_default_params();
        let device = FidoKeyHid::new(&hid_params).unwrap();
        let cid = ctaphid::ctaphid_init(&device).unwrap();

        let send_payload =
            client_pin_command::create_payload(client_pin_command::SubCommand::GetKeyAgreement)
                .unwrap();
        let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload).unwrap();
        //println!("{}",util::to_hex_str(&send_payload));

        let key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor).unwrap();
        key_agreement.print("authenticatorClientPIN (0x06) - getKeyAgreement");

        assert!(true);
    }

    #[test]
    fn test_make_credential_with_pin_non_rk_command() {
        let rpid = "test.com";
        let challenge = b"this is challenge".to_vec();
        // create windows
        let pin_auth = hex::decode("6F79FB322D74972ACAA844C10C183BF7").unwrap();
        let check = "01A7015820E61E2BD6C4612662960B159CD54CF8EFF1A998C89B3742519D11F85E0F5E787602A262696468746573742E636F6D646E616D656003A36269644100646E616D6561206B646973706C61794E616D6561200481A263616C672664747970656A7075626C69632D6B657907A262726BF4627576F508506F79FB322D74972ACAA844C10C183BF70901".to_string();

        // create cmmand
        let send_payload = {
            let mut params =
                make_credential_command::Params::new(rpid, challenge.to_vec(), [].to_vec());
            params.option_rk = false; // non rk
            params.option_uv = true;

            println!(
                "- client_data_hash({:02})    = {:?}",
                params.client_data_hash.len(),
                util::to_hex_str(&params.client_data_hash)
            );

            params.pin_auth = pin_auth.to_vec();

            make_credential_command::create_payload(params)
        };

        let command = hex::encode(send_payload).to_uppercase();
        assert_eq!(command, check);
    }

    #[test]
    fn test_create_pin_auth() {
        let out_bytes = hex::decode("1A81CD600A1F6CF4BE5260FE3257B241").unwrap();
        let client_data_hash =
            hex::decode("E61E2BD6C4612662960B159CD54CF8EFF1A998C89B3742519D11F85E0F5E7876")
                .unwrap();
        //println!("- out_bytes({:?})       = {:?}", out_bytes.len(), util::to_hex_str(&out_bytes));
        let check = "F0AC99D6AAD2E199AF9CF25F6568A6F5".to_string();

        let pin_token_dec = pintoken::PinToken {
            signing_key: hmac::SigningKey::new(&digest::SHA256, &out_bytes),
            key: out_bytes.to_vec(),
        };
        let pin_auth = pin_token_dec.authenticate_v1(&client_data_hash);

        assert_eq!(check, hex::encode(pin_auth).to_uppercase());
    }
}
