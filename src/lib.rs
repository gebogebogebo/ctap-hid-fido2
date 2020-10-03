/*!
## Examples

#### get_info()

```Rust
use ctap_hid_fido2;

fn main() {
    println!("get_info()");
    let infos = match ctap_hid_fido2::get_info(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => result,
        Err(error) => {
            println!("error: {:?}", error);
            return;
        },
    };    
    for (key, value) in infos {
        println!("- {} / {}", key, value);
    }
}
```

console

```sh
get_info()
- versions / U2F_V2
- versions / FIDO_2_0
- extensions / hmac-secret
- aaguid / FA2B99DC9E3942578F924A30D23C4118
- options-rk / true
- options-up / true
- options-plat / false
- options-clientPin / true
- max_msg_size / 1200
- pin_protocols / 1
```



#### get_pin_retries()

```Rust
use ctap_hid_fido2;

fn main() {
    println!("get_pin_retries()");
    let retry = match ctap_hid_fido2::get_pin_retries(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => result,
        Err(error) => {
            println!("error: {:?}", error);
            return;
        },
    };    
    println!("- pin retry = {}", retry);
}
```

console

```sh
get_pin_retries()
- pin retry = 8
```



#### make_credential()

#### get_assertion()

```Rust
use ctap_hid_fido2;
use ctap_hid_fido2::util;

fn main() {
    println!("----- test-with-pin-non-rk start -----");

    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let pin = "1234";

    println!("make_credential()");
    let cre_id = match ctap_hid_fido2::make_credential(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        pin,
    ) {
        Ok(result) => result.credential_id,
        Err(err) => {
            println!("- Register Error {:?}", err);
            return;
        }
    };

    println!("- Register Success!!");
    println!(
        "- credential_id({:02}) = {:?}",
        cre_id.len(),
        util::to_hex_str(&cre_id)
    );

    println!("get_assertion_with_pin()");
    let att = match ctap_hid_fido2::get_assertion(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        &cre_id,
        pin,
    ) {
        Ok(result) => result,
        Err(err) => {
            println!("- Authenticate Error {:?}", err);
            return;
        }
    };
    println!("- Authenticate Success!!");
    println!("- sign_count = {:?}", att.sign_count);
    println!(
        "- signature({:02}) = {:?}",
        att.signature.len(),
        util::to_hex_str(&att.signature)
    );

    println!("----- test-with-pin-non-rk end -----");
}
```

console

```sh
----- test-with-pin-non-rk start -----
make_credential()
- touch fido key
- Register Success!!
- credential_id(64) = "65CE1DDB3B5BF9FDD85664F324D575478783121DE0D4489E0CB5BAB24ED8C8F4965235E0F80011B7D13391295A42C964FB256DC02768B1A3DF434FEB83EE1CE7"
get_assertion_with_pin()
- touch fido key
- Authenticate Success!!
- sign_count = 271
- signature(71) = "304502201B03779653849389198BF8291C0170AD51BBC0C714E2AF1D260A3B3413E75D51022100DA9053755FD1C74214F70E58FCB1E8E302C617BA69B297AC855D15BF4D5CA748"
----- test-with-pin-non-rk end -----
```



#### wink

Just blink the LED on the FIDO key

```Rust
use ctap_hid_fido2;

fn main() {
    println!("----- wink start -----");
    if let Err(msg) = ctap_hid_fido2::wink(&ctap_hid_fido2::HidParam::get_default_params()){
        println!("error: {:?}", msg);
    }
    println!("----- wink end -----");
}
```

*/

mod client_pin_command;
mod client_pin_response;
mod cose;
mod ctaphid;
mod get_assertion_command;
pub mod get_assertion_params;
mod get_assertion_response;
mod get_next_assertion_command;
mod get_info_command;
mod get_info_response;
mod make_credential_command;
pub mod make_credential_params;
mod make_credential_response;
mod p256;
mod pintoken;
mod ss;
pub mod util;

/// HID device vendor ID , product ID
pub struct HidParam {
    /// vendor ID
    pub vid: u16,
    /// product ID
    pub pid: u16,
}

impl HidParam {
    /// Generate HID parameters for FIDO key devices
    /// - yubikey black = vid:0x1050 , pid:0x0402
    /// - yubikey blue = vid:0x1050 , pid:0x0120
    /// - biopass = vid:0x096E , pid:0x085D
    /// - all in pass = vid:0x096E , pid:0x0866
    /// - solokey = vid:0x0483 , pid:0xa2ca
    pub fn get_default_params() -> Vec<HidParam> {
        vec![
            HidParam {
                vid: 0x1050,
                pid: 0x0402,
            }, // yubikey black
            HidParam {
                vid: 0x1050,
                pid: 0x0120,
            }, // yubikey blue
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
        ]
    }
}

/// Get HID devices
pub fn get_hid_devices() -> Vec<(String, HidParam)> {
    ctaphid::get_hid_devices(None)
}

/// Get HID FIDO devices
pub fn get_fidokey_devices() -> Vec<(String, HidParam)> {
    ctaphid::get_hid_devices(Some(ctaphid::USAGE_PAGE_FIDO))
}

/// Lights the LED on the FIDO key
pub fn wink(hid_params: &[HidParam]) -> Result<(), &'static str> {
    let device = ctaphid::connect_device(hid_params, ctaphid::USAGE_PAGE_FIDO)?;
    let cid = ctaphid::ctaphid_init(&device);
    ctaphid::ctaphid_wink(&device, &cid);
    Ok(())
}

/// Get FIDO key information
pub fn get_info(hid_params: &[HidParam]) -> Result<Vec<(String, String)>, &'static str> {
    let device = ctaphid::connect_device(hid_params, ctaphid::USAGE_PAGE_FIDO)?;
    let cid = ctaphid::ctaphid_init(&device);

    let send_payload = get_info_command::create_payload();
    //println!("{}",util::to_hex_str(&send_payload));

    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload).unwrap();

    let info = get_info_response::parse_cbor(&response_cbor).unwrap();

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
pub fn get_pin_retries(hid_params: &[HidParam]) -> Result<i32, &'static str> {
    let device = ctaphid::connect_device(hid_params, ctaphid::USAGE_PAGE_FIDO)?;
    let cid = ctaphid::ctaphid_init(&device);

    let send_payload =
        client_pin_command::create_payload(client_pin_command::SubCommand::GetRetries).unwrap();
    //println!("{}",util::to_hex_str(&send_payload));

    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload).unwrap();

    let pin = client_pin_response::parse_cbor_client_pin_get_retries(&response_cbor).unwrap();
    //println!("authenticatorClientPIN (0x06) - getRetries");
    //println!("- retries       = {:?}", pin.retries);

    Ok(pin.retries)
}

/// Registration command.Generate credentials(with PIN,non Resident Key)
pub fn make_credential(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    pin: &str,
) -> Result<make_credential_params::Attestation, String> {
    let result = make_credential_inter(hid_params, rpid, challenge, pin, false, true,None)?;
    Ok(result)
}

/// Registration command.Generate credentials(with PIN ,Resident Key)
pub fn make_credential_rk(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    pin: &str,
    rkparam: &make_credential_params::RkParam,
) -> Result<make_credential_params::Attestation, String> {
    let result = make_credential_inter(hid_params, rpid, challenge, pin, true, true,Some(rkparam))?;
    Ok(result)
}

/// Registration command.Generate credentials(without PIN ,non Resident Key)
pub fn make_credential_without_pin(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
) -> Result<make_credential_params::Attestation, String> {
    let result = make_credential_inter(hid_params, rpid, challenge, "", false, false,None)?;
    Ok(result)
}

fn make_credential_inter(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    pin: &str,
    rk: bool,
    uv: bool,
    rkparam: Option<&make_credential_params::RkParam>,
) -> Result<make_credential_params::Attestation, String> {
    // init
    let device = ctaphid::connect_device(hid_params, ctaphid::USAGE_PAGE_FIDO)?;
    let cid = ctaphid::ctaphid_init(&device);

    let user_id = {
        if let Some(rkp) = rkparam{
            rkp.user_id.to_vec()
        }else{
            [].to_vec()
        }
    };

    // create cmmand
    let send_payload = {
        let mut params =
            make_credential_command::Params::new(rpid, challenge.to_vec(), user_id);
        params.option_rk = rk;
        params.option_uv = uv;

        if let Some(rkp) = rkparam{
            params.user_name = rkp.user_name.to_string();
            params.user_display_name = rkp.user_display_name.to_string();
        }
        //println!("- client_data_hash({:02})    = {:?}", params.client_data_hash.len(),util::to_hex_str(&params.client_data_hash));

        // get pintoken & create pin auth
        if pin.len() > 0 {
            let pin_auth =
                get_pin_token(&device, &cid, pin.to_string())?.auth(&params.client_data_hash);
            //let pin_auth = hex::decode("FF95E70BB8008BB1B0EE8296C0A16130").unwrap();

            //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));
            params.pin_auth = pin_auth.to_vec();
        }

        make_credential_command::create_payload(params)
    };
    println!("- make_credential({:02})    = {:?}", send_payload.len(),util::to_hex_str(&send_payload));

    // send & response
    let response_cbor = match ctaphid::ctaphid_cbor(&device, &cid, &send_payload) {
        Ok(n) => n,
        Err(err) => {
            let msg = format!("make_credential_command err = {}", util::get_ctap_status_message(err));
            return Err(msg);
        }
    };

    let att = make_credential_response::parse_cbor(&response_cbor).unwrap();
    Ok(att)
}

/// Authentication command(with PIN , non Resident Key)
pub fn get_assertion(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    credential_id: &[u8],
    pin: &str,
) -> Result<get_assertion_params::Assertion, String> {
    let asss = get_assertion_inter(hid_params, rpid, challenge, credential_id, pin, true, true)?;
    Ok(asss[0].clone())
}

pub fn get_assertions_rk(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    pin: &str,
) -> Result<Vec<get_assertion_params::Assertion>, String> {
    let dmy:[u8;0] = [];
    let asss = get_assertion_inter(hid_params, rpid, challenge, &dmy, pin, true, true)?;
    Ok(asss)
}


fn get_assertion_inter(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    credential_id: &[u8],
    pin: &str,
    up: bool,
    uv: bool,
) -> Result<Vec<get_assertion_params::Assertion>, String> {
    // init
    let device = ctaphid::connect_device(hid_params, ctaphid::USAGE_PAGE_FIDO)?;
    let cid = ctaphid::ctaphid_init(&device);

    // pin token
    let pin_token = get_pin_token(&device, &cid, pin.to_string())?;

    // create cmmand
    let send_payload = {
        let mut params =
            get_assertion_command::Params::new(rpid, challenge.to_vec(), credential_id.to_vec());
        params.option_up = up;
        params.option_uv = uv;

        // create pin auth
        let pin_auth = pin_token.auth(&params.client_data_hash);
        //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));
        params.pin_auth = pin_auth.to_vec();

        get_assertion_command::create_payload(params)
    };
    //println!("- get_assertion({:02})    = {:?}", send_payload.len(),util::to_hex_str(&send_payload));

    // send & response
    let response_cbor = match ctaphid::ctaphid_cbor(&device, &cid, &send_payload) {
        Ok(n) => n,
        Err(err) => {
            let msg = format!("get_assertion_command err = {}", util::get_ctap_status_message(err));
            return Err(msg);
        }
    };
    println!("- response_cbor({:02})    = {:?}", response_cbor.len(),util::to_hex_str(&response_cbor));

    let ass = get_assertion_response::parse_cbor(&response_cbor).unwrap();

    let mut asss = vec![ass];

    for _ in 0..(asss[0].number_of_credentials-1){
        let ass = get_next_assertion(&device, &cid).unwrap();
        asss.push(ass);
    }

    Ok(asss)
}

pub fn get_next_assertion(    
    device: &hidapi::HidDevice,
    cid: &[u8],
) -> Result<get_assertion_params::Assertion, String> {

    let send_payload = get_next_assertion_command::create_payload();

    // send & response
    let response_cbor = match ctaphid::ctaphid_cbor(&device, &cid, &send_payload) {
        Ok(n) => n,
        Err(err) => {
            let msg = format!("get_next_assertion_command err = {}", util::get_ctap_status_message(err));
            return Err(msg);
        }
    };
    //println!("- response_cbor({:02})    = {:?}", response_cbor.len(),util::to_hex_str(&response_cbor));

    let ass = get_assertion_response::parse_cbor(&response_cbor).unwrap();
    Ok(ass)
}

fn get_pin_token(
    device: &hidapi::HidDevice,
    cid: &[u8],
    pin: String,
) -> Result<pintoken::PinToken, String> {
    if pin.len() > 0 {
        let send_payload =
            client_pin_command::create_payload(client_pin_command::SubCommand::GetKeyAgreement)
                .unwrap();
        let response_cbor = ctaphid::ctaphid_cbor(device, cid, &send_payload).unwrap();

        let key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor).unwrap();
        //key_agreement.print("authenticatorClientPIN (0x06) - getKeyAgreement");

        let shared_secret = ss::SharedSecret::new(&key_agreement).unwrap();
        //shared_secret.public_key.print("SharedSecret  - Public Key");

        let pin_hash_enc = shared_secret.encrypt_pin(&pin).unwrap();
        //println!("- PIN hash enc({:?})       = {:?}", pin_hash_enc.len(), util::to_hex_str(&pin_hash_enc));

        let send_payload = client_pin_command::create_payload_get_pin_token(
            &shared_secret.public_key,
            pin_hash_enc.to_vec(),
        );
        let response_cbor = match ctaphid::ctaphid_cbor(&device, &cid, &send_payload) {
            Ok(result) => result,
            Err(err) => {
                let msg = format!("get_pin_token_command err = {}", util::get_ctap_status_message(err));
                return Err(msg);
            }
        };

        // get pin_token (enc)
        let mut pin_token_enc =
            client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor).unwrap();
        //println!("- pin_token_enc({:?})       = {:?}", pin_token_enc.len(), util::to_hex_str(&pin_token_enc));

        // pintoken -> dec(pintoken)
        let pin_token_dec = shared_secret.decrypt_token(&mut pin_token_enc).unwrap();
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
        let params = HidParam::get_default_params();
        let device = ctaphid::connect_device(&params, ctaphid::USAGE_PAGE_FIDO).unwrap();
        let cid = ctaphid::ctaphid_init(&device);

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

        let att = make_credential(&params, rpid, &challenge, pin).unwrap();
        att.print("Attestation");

        let ass = get_assertion(&params, rpid, &challenge, &att.credential_id, pin).unwrap();
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

            // create pin auth
            //let pin_auth = pin_token.unwrap().auth(&params.client_data_hash);

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
