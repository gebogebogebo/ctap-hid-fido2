/*!
## Examples

[-> Examples](https://github.com/gebogebogebo/ctap-hid-fido2/blob/master/README.md#examples)

*/

mod client_pin_command;
mod client_pin_response;
mod cose;
mod ctaphid;
mod ctapihd_nitro;
mod get_assertion_command;
pub mod get_assertion_params;
mod get_assertion_response;
mod get_info_command;
mod get_info_response;
mod get_next_assertion_command;
mod make_credential_command;
pub mod make_credential_params;
mod make_credential_response;
pub mod nitrokey;
mod p256;
mod pintoken;
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
pub fn hello() { println!("Hello, I'm Windows!"); }

#[cfg(target_os = "linux")]
pub fn hello() { println!("Hello, I'm Linux!"); }

#[cfg(target_os = "macos")]
pub fn hello() { println!("hello, I'm MacOS."); }

/// Get HID devices
pub fn get_hid_devices() -> Vec<(String, HidParam)> {
    fidokey::FidoKeyHid::get_hid_devices(None)
}

/// Get HID FIDO devices
pub fn get_fidokey_devices() -> Vec<(String, HidParam)> {
    fidokey::FidoKeyHid::get_hid_devices(Some(0xf1d0))
}

/// Lights the LED on the FIDO key
pub fn wink(hid_params: &[HidParam]) -> Result<(), String> {
    let device = fidokey::FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;
    ctaphid::ctaphid_wink(&device, &cid)?;
    Ok(())
}

/// Get FIDO key information
pub fn get_info(hid_params: &[HidParam]) -> Result<Vec<(String, String)>, String> {
    let device = fidokey::FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;

    let send_payload = get_info_command::create_payload();
    //println!("{}",util::to_hex_str(&send_payload));

    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;

    let info = get_info_response::parse_cbor(&response_cbor)?;

    let mut result: Vec<(String, String)> = vec![];

    for i in info.versions {
        result.push(("versions".to_string(), i));
    }
    for i in info.extensions {
        result.push(("extensions".to_string(), i));
    }
    result.push(("aaguid".to_string(), util::to_hex_str(&info.aaguid)));

    for i in info.options {
        result.push((format!("options-{}", i.0), i.1.to_string()));
    }

    result.push(("max_msg_size".to_string(), info.max_msg_size.to_string()));

    for i in info.pin_protocols {
        result.push(("pin_protocols".to_string(), i.to_string()));
    }

    Ok(result)
}

/// Get PIN retry count
pub fn get_pin_retries(hid_params: &[HidParam]) -> Result<i32, String> {
    let device = fidokey::FidoKeyHid::new(hid_params)?;
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
    let result = make_credential_inter(hid_params, rpid, challenge, pin, false, None)?;
    Ok(result)
}

/// Registration command.Generate credentials(with PIN ,Resident Key)
pub fn make_credential_rk(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    pin: Option<&str>,
    rkparam: &make_credential_params::RkParam,
) -> Result<make_credential_params::Attestation, String> {
    let result = make_credential_inter(hid_params, rpid, challenge, pin, true, Some(rkparam))?;
    Ok(result)
}

/// Registration command.Generate credentials(without PIN ,non Resident Key)
pub fn make_credential_without_pin(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
) -> Result<make_credential_params::Attestation, String> {
    let result = make_credential_inter(hid_params, rpid, challenge, None, false, None)?;
    Ok(result)
}

fn make_credential_inter(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    pin: Option<&str>,
    rk: bool,
    rkparam: Option<&make_credential_params::RkParam>,
) -> Result<make_credential_params::Attestation, String> {
    // init
    let device = fidokey::FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;

    // uv
    let uv = {
        match pin {
            Some(_) => false,
            None => true,
        }
    };

    let user_id = {
        if let Some(rkp) = rkparam {
            rkp.user_id.to_vec()
        } else {
            [].to_vec()
        }
    };

    // create cmmand
    let send_payload = {
        let mut params = make_credential_command::Params::new(rpid, challenge.to_vec(), user_id);
        params.option_rk = rk;
        params.option_uv = uv;

        if let Some(rkp) = rkparam {
            params.user_name = rkp.user_name.to_string();
            params.user_display_name = rkp.user_display_name.to_string();
        }
        //println!("- client_data_hash({:02})    = {:?}", params.client_data_hash.len(),util::to_hex_str(&params.client_data_hash));

        // get pintoken & create pin auth
        if let Some(pin) = pin {
            if pin.len() > 0 {
                let pin_auth =
                    get_pin_token(&device, &cid, pin.to_string())?.auth(&params.client_data_hash);

                //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));
                params.pin_auth = pin_auth.to_vec();
            }
        }

        make_credential_command::create_payload(params)
    };

    if util::is_debug() == true {
        println!(
            "- make_credential({:02})    = {:?}",
            send_payload.len(),
            util::to_hex_str(&send_payload)
        );
    }

    // send & response
    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;

    let att = make_credential_response::parse_cbor(&response_cbor)?;
    Ok(att)
}

/// Authentication command(with PIN , non Resident Key)
pub fn get_assertion(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    credential_id: &[u8],
    pin: Option<&str>,
) -> Result<get_assertion_params::Assertion, String> {
    let asss = get_assertion_inter(hid_params, rpid, challenge, credential_id, pin, true)?;
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
    let asss = get_assertion_inter(hid_params, rpid, challenge, &dmy, pin, true)?;
    Ok(asss)
}

fn get_assertion_inter(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    credential_id: &[u8],
    pin: Option<&str>,
    up: bool,
) -> Result<Vec<get_assertion_params::Assertion>, String> {
    // init
    let device = fidokey::FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;

    // uv
    let uv = {
        match pin {
            Some(_) => false,
            None => true,
        }
    };

    // pin token
    let pin_token = {
        if let Some(pin) = pin {
            Some(get_pin_token(&device, &cid, pin.to_string())?)
        } else {
            None
        }
    };

    //let pin_token = get_pin_token(&device, &cid, pin.to_string())?;

    // create cmmand
    let send_payload = {
        let mut params =
            get_assertion_command::Params::new(rpid, challenge.to_vec(), credential_id.to_vec());
        params.option_up = up;
        params.option_uv = uv;

        // create pin auth
        if let Some(pin_token) = pin_token {
            let pin_auth = pin_token.auth(&params.client_data_hash);
            //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));
            params.pin_auth = pin_auth.to_vec();
        }

        get_assertion_command::create_payload(params)
    };
    //println!("- get_assertion({:02})    = {:?}", send_payload.len(),util::to_hex_str(&send_payload));

    // send & response
    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;

    if util::is_debug() == true {
        println!(
            "- response_cbor({:02})    = {:?}",
            response_cbor.len(),
            util::to_hex_str(&response_cbor)
        );
    }

    let ass = get_assertion_response::parse_cbor(&response_cbor)?;

    let mut asss = vec![ass];

    for _ in 0..(asss[0].number_of_credentials - 1) {
        let ass = get_next_assertion(&device, &cid)?;
        asss.push(ass);
    }

    Ok(asss)
}

fn get_next_assertion(
    device: &fidokey::FidoKeyHid,
    cid: &[u8],
) -> Result<get_assertion_params::Assertion, String> {
    let send_payload = get_next_assertion_command::create_payload();

    // send & response
    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;

    //println!("- response_cbor({:02})    = {:?}", response_cbor.len(),util::to_hex_str(&response_cbor));

    let ass = get_assertion_response::parse_cbor(&response_cbor)?;
    Ok(ass)
}

fn get_pin_token(
    device: &fidokey::FidoKeyHid,
    cid: &[u8],
    pin: String,
) -> Result<pintoken::PinToken, String> {
    if pin.len() > 0 {
        let send_payload =
            client_pin_command::create_payload(client_pin_command::SubCommand::GetKeyAgreement)?;
        let response_cbor = ctaphid::ctaphid_cbor(device, cid, &send_payload)?;

        let key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

        let shared_secret = ss::SharedSecret::new(&key_agreement)?;
        //shared_secret.public_key.print("SharedSecret  - Public Key");

        let pin_hash_enc = shared_secret.encrypt_pin(&pin)?;
        //println!("- PIN hash enc({:?})       = {:?}", pin_hash_enc.len(), util::to_hex_str(&pin_hash_enc));

        let send_payload = client_pin_command::create_payload_get_pin_token(
            &shared_secret.public_key,
            pin_hash_enc.to_vec(),
        );

        let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;

        // get pin_token (enc)
        let mut pin_token_enc =
            client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;
        //println!("- pin_token_enc({:?})       = {:?}", pin_token_enc.len(), util::to_hex_str(&pin_token_enc));

        // pintoken -> dec(pintoken)
        let pin_token_dec = shared_secret.decrypt_token(&mut pin_token_enc)?;
        //println!("- pin_token_dec({:?})       = {:?}", pin_token_dec.len(), util::to_hex_str(&pin_token_dec));

        Ok(pin_token_dec)
    } else {
        Err("pin not set".to_string())
    }
}

//
// cargo test -- --test-threads=1
//
#[cfg(test)]
mod tests {
    use super::*;
    //use serde_cbor::Value;
    //use num::NumCast;
    use ring::{digest, hmac};

    #[test]
    fn test_get_hid_devices() {
        get_hid_devices();
        assert!(true);
    }

    #[test]
    fn test_wink() {
        let hid_params = HidParam::get_default_params();
        wink(&hid_params).unwrap();
        assert!(true);
    }

    #[test]
    fn test_get_info() {
        let hid_params = HidParam::get_default_params();
        get_info(&hid_params).unwrap();
        assert!(true);
    }

    #[test]
    fn test_client_pin_get_retries() {
        let hid_params = HidParam::get_default_params();
        let retry = get_pin_retries(&hid_params);
        println!("- retries = {:?}", retry);
        assert!(true);
    }

    #[test]
    fn test_client_pin_get_keyagreement() {
        let hid_params = HidParam::get_default_params();
        let device = fidokey::FidoKeyHid::new(&hid_params).unwrap();
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
    fn test_make_credential_with_pin_non_rk() {
        // parameter
        let rpid = "test.com";
        let challenge = b"this is challenge".to_vec();
        let pin = "1234";

        let params = HidParam::get_default_params();

        let att = make_credential(&params, rpid, &challenge, Some(pin)).unwrap();
        att.print("Attestation");

        let ass = get_assertion(&params, rpid, &challenge, &att.credential_id, Some(pin)).unwrap();
        ass.print("Assertion");

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

        let pin_token_dec = pintoken::PinToken(hmac::SigningKey::new(&digest::SHA256, &out_bytes));
        let pin_auth = pin_token_dec.auth(&client_data_hash);

        assert_eq!(check, hex::encode(pin_auth).to_uppercase());
    }
}
