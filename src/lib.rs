/*!
### Examples

#### get_info

```Rust
println!("- get_info");
let hid_params = ctap_hid_fido2::HidParam::get_default_params();
let result = match ctap_hid_fido2::get_info(&hid_params) {
    Ok(info) => info,
    Err(error) => {
        println!("error: {:?}", error);
        return;
    },
};    
for (key, value) in result {
    println!("{} / {}", key, value);
}
```

console

```sh
- get_info
versions / U2F_V2
versions / FIDO_2_0
extensions / hmac-secret
aaguid / FA2B99DC9E3942578F924A30D23C4118
options-rk / true
options-up / true
options-plat / false
options-clientPin / true
max_msg_size / 1200
pin_protocols / 1
```


#### get_pin_retries

```Rust
println!("- get_pin_retries");
let retry = match ctap_hid_fido2::get_pin_retries(&hid_params) {
    Ok(result) => result,
    Err(error) => {
        println!("error: {:?}", error);
        return;
    },
};    
println!("pin retry = {}", retry);
```

console

```sh
- get_pin_retries
pin retry = 8
```


#### make_credential_with_pin_non_rk

```Rust
println!("- make_credential_with_pin_non_rk");
let rpid = "test.com";
let challenge = b"this is challenge".to_vec();
let pin = "1234";

let hid_params = ctap_hid_fido2::HidParam::get_default_params();
let result = match ctap_hid_fido2::make_credential_with_pin_non_rk(&hid_params,rpid,&challenge,pin){
    Ok(result) => result,
    Err(err) => {
        println!("{:?}",err);
        return;
    }
};
println!("credential_id({:02})  = {:?}", result.credential_id.len(),util::to_hex_str(&result.credential_id));
```

console

```sh
- make_credential_with_pin_non_rk
keep alive
...
credential_id(64)  = "CEB92D2EEE7888246DF4FF9A186268511EA270675119E679164AD910B74A9ED1E2D7FCEA81853FDB5149A3FD00F3FB63ED3D74ABE6C143D92B41639E7564FA00"

```


#### get_assertion_with_pin

```Rust
println!("- get_assertion_with_pin");
let hid_params = ctap_hid_fido2::HidParam::get_default_params();
let rpid = "test.com";
let challenge = b"this is challenge".to_vec();
let cre_id = b"set credential id".to_vec();
let pin = "1234";

let result = match ctap_hid_fido2::get_assertion_with_pin(&hid_params,rpid,&challenge,&cre_id,pin){
    Ok(result) => result,
    Err(err) => {
        println!("{:?}",err);
        return;
    }
};
println!("number_of_credentials = {:?}",result.number_of_credentials);
```

console

```sh
- get_assertion_with_pin
keep alive
...
number_of_credentials = 0
```

#### wink
Only the FIDO key glows

```Rust
let hid_params = ctap_hid_fido2::HidParam::get_default_params();
let result = match ctap_hid_fido2::wink(&hid_params) {
    Ok(()) => (),
    Err(error) => {
        println!("error: {:?}", error);
        return;
    },
};
```

*/


mod ctaphid;
mod get_info_command;
mod get_info_response;
mod make_credential_command;
mod make_credential_response;
mod make_credential_with_pin_non_rk_result;
mod get_assertion_command;
mod get_assertion_response;
mod get_assertion_with_pin_result;
mod client_pin_command;
mod client_pin_response;
pub mod util;
mod cose;
mod p256;
mod ss;
mod pintoken;

extern crate crypto as rust_crypto;

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
pub fn get_default_params() -> Vec<HidParam>{
        vec![
            HidParam{vid:0x1050,pid:0x0402},        // yubikey black
            HidParam{vid:0x1050,pid:0x0120},        // yubikey blue
            HidParam{vid:0x096E,pid:0x085D},        // biopass
            HidParam{vid:0x096E,pid:0x0866},        // all in pass
            HidParam{vid:0x0483,pid:0xa2ca},        // solokey
        ]
    }
}

fn get_pin_token(device:&hidapi::HidDevice,cid:&[u8],pin:String)->Result<pintoken::PinToken,String>
{
    if pin.len() > 0 {
        let send_payload = client_pin_command::create_payload(client_pin_command::SubCommand::GetKeyAgreement).unwrap();
        let response_cbor = ctaphid::ctaphid_cbor(device,cid,&send_payload).unwrap();
    
        let key_agreement = client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor).unwrap();
        //key_agreement.print("authenticatorClientPIN (0x06) - getKeyAgreement");        
    
        let shared_secret = ss::SharedSecret::new(&key_agreement).unwrap();
        //shared_secret.public_key.print("SharedSecret  - Public Key");
        
        let pin_hash_enc = shared_secret.encrypt_pin(&pin).unwrap();
        //println!("- PIN hash enc({:?})       = {:?}", pin_hash_enc.len(), util::to_hex_str(&pin_hash_enc));
    
        let send_payload = client_pin_command::create_payload_get_pin_token(&shared_secret.public_key,pin_hash_enc.to_vec());
        let response_cbor = match ctaphid::ctaphid_cbor(&device,&cid,&send_payload){
            Ok(result) => result,
            Err(err) => {
                let msg = format!("get_pin_token_command err = 0x{:02x}",err);
                return Err(msg);
            }
        };
        
        // get pin_token (enc)
        let mut pin_token_enc = client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor).unwrap();
        //println!("- pin_token_enc({:?})       = {:?}", pin_token_enc.len(), util::to_hex_str(&pin_token_enc));
    
        // pintoken -> dec(pintoken)
        let pin_token_dec = shared_secret.decrypt_token(&mut pin_token_enc).unwrap();
        //println!("- pin_token_dec({:?})       = {:?}", pin_token_dec.len(), util::to_hex_str(&pin_token_dec));

        Ok(pin_token_dec)
    }else{
        Err("pin not set".to_string())
    }
}

/// Get HID devices
pub fn get_hid_devices()->Vec<(String,HidParam)>{
    ctaphid::get_hid_devices(None)
}

/// Get HID FIDO devices
pub fn get_fidokey_devices()->Vec<(String,HidParam)>{
    ctaphid::get_hid_devices(Some(ctaphid::USAGE_PAGE_FIDO))
}

/// Lights the LED on the FIDO key
pub fn wink(hid_params:&[HidParam])->Result<(),&'static str>{
    let device = ctaphid::connect_device(hid_params,ctaphid::USAGE_PAGE_FIDO)?;
    let cid = ctaphid::ctaphid_init(&device);
    ctaphid::ctaphid_wink(&device,&cid);
    Ok(())
}

/// Get FIDO key information
pub fn get_info(hid_params:&[HidParam])->Result<Vec<(String,String)>,&'static str>{
    let device = ctaphid::connect_device(hid_params,ctaphid::USAGE_PAGE_FIDO)?;
    let cid = ctaphid::ctaphid_init(&device);

    let send_payload = get_info_command::create_payload();
    //println!("{}",util::to_hex_str(&send_payload));

    let response_cbor = ctaphid::ctaphid_cbor(&device,&cid,&send_payload).unwrap();

    let info = get_info_response::parse_cbor(&response_cbor).unwrap();

    let mut result:Vec<(String,String)> = vec![];

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

    //println!("authenticatorGetInfo (0x04)");
    //println!("- versions      = {:?}", info.versions);
    //println!("- extensions    = {:?}", info.extensions);
    //println!("- aaguid({:?})    = {:?}", info.aaguid.len(),util::to_hex_str(&info.aaguid));
    //println!("- options       = {:?}", info.options);
    //println!("- max_msg_size  = {:?}", info.max_msg_size);
    //println!("- pin_protocols = {:?}", info.pin_protocols);

    Ok(result)
}

/// Get PIN retry count
pub fn get_pin_retries(hid_params:&[HidParam])->Result<i32,&'static str>{
    let device = ctaphid::connect_device(hid_params,ctaphid::USAGE_PAGE_FIDO)?;
    let cid = ctaphid::ctaphid_init(&device);

    let send_payload = client_pin_command::create_payload(client_pin_command::SubCommand::GetRetries).unwrap();
    //println!("{}",util::to_hex_str(&send_payload));

    let response_cbor = ctaphid::ctaphid_cbor(&device,&cid,&send_payload).unwrap();

    let pin = client_pin_response::parse_cbor_client_pin_get_retries(&response_cbor).unwrap();
    //println!("authenticatorClientPIN (0x06) - getRetries");
    //println!("- retries       = {:?}", pin.retries);

    Ok(pin.retries)
}

/// Registration command.Generate credentials
pub fn make_credential_with_pin_non_rk(hid_params:&[HidParam],rpid:&str,challenge:&[u8],pin:&str)->Result<make_credential_with_pin_non_rk_result::MakeCredentialWithPinNonRkResult,String> {

    // init
    let device = ctaphid::connect_device(hid_params,ctaphid::USAGE_PAGE_FIDO)?;
    let cid = ctaphid::ctaphid_init(&device);

    // pin token
    let pin_token = get_pin_token(&device,&cid,pin.to_string())?;

    // create cmmand
    let send_payload = 
    {
        let mut params = make_credential_command::Params::new(rpid,challenge.to_vec(),[].to_vec());
        //params.user_name = user_name.to_string();
        //params.user_display_name = String::from("DispUser");
        params.option_rk = false; // non rk
        params.option_uv = true;

        //println!("- client_data_hash({:02})    = {:?}", params.client_data_hash.len(),util::to_hex_str(&params.client_data_hash));

        // create pin auth
        let pin_auth = pin_token.auth(&params.client_data_hash);
        //let pin_auth = hex::decode("FF95E70BB8008BB1B0EE8296C0A16130").unwrap();

        //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));
        params.pin_auth = pin_auth.to_vec();

        make_credential_command::create_payload(params)
    };
    //println!("- make_credential({:02})    = {:?}", send_payload.len(),util::to_hex_str(&send_payload));

    // send & response
    let response_cbor = match ctaphid::ctaphid_cbor(&device,&cid,&send_payload){
        Ok(n) => n,
        Err(err) => {
            let msg = format!("make_credential_command err = 0x{:02x}",err);
            return Err(msg);
        }
    };

    let att = make_credential_response::parse_cbor(&response_cbor).unwrap();

    /*
    println!("authenticatorMakeCredential (0x01)");
    println!("- fmt                                     = {:?}", att.fmt);
    println!("- rpid_hash({:02})                           = {:?}", att.rpid_hash.len(),util::to_hex_str(&att.rpid_hash));
    println!("- flags_user_present_result               = {:?}", att.flags_user_present_result);
    println!("- flags_user_verified_result              = {:?}", att.flags_user_verified_result);
    println!("- flags_attested_credential_data_included = {:?}", att.flags_attested_credential_data_included);
    println!("- flags_extensiondata_included            = {:?}", att.flags_extension_data_included);
    println!("- sign_count                              = {:?}", att.sign_count);
    println!("- aaguid({:02})                              = {:?}", att.aaguid.len(),util::to_hex_str(&att.aaguid));
    println!("- credential_id({:02})                       = {:?}", att.credential_id.len(),util::to_hex_str(&att.credential_id));
    */

    let result = make_credential_with_pin_non_rk_result::MakeCredentialWithPinNonRkResult{
        credential_id: att.credential_id.to_vec(),
    };
    Ok(result)
}

/// Authentication command
pub fn get_assertion_with_pin(hid_params:&[HidParam],rpid:&str,challenge:&[u8],credential_id:&[u8],pin:&str) ->Result<get_assertion_with_pin_result::GetAssertionWithPinResult,String>{

    // init
    let device = ctaphid::connect_device(hid_params,ctaphid::USAGE_PAGE_FIDO)?;
    let cid = ctaphid::ctaphid_init(&device);

    // pin token
    let pin_token = get_pin_token(&device,&cid,pin.to_string())?;

    // create cmmand
    let send_payload = 
    {
        let mut params = get_assertion_command::Params::new(rpid,challenge.to_vec(),credential_id.to_vec());
        params.option_up=true;
        params.option_uv=true;

        // create pin auth
        let pin_auth = pin_token.auth(&params.client_data_hash);
        //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));
        params.pin_auth = pin_auth.to_vec();

        get_assertion_command::create_payload(params)
    };

    // send & response
    let response_cbor = ctaphid::ctaphid_cbor(&device,&cid,&send_payload).unwrap();

    let ass = get_assertion_response::parse_cbor(&response_cbor).unwrap();
    /*
    println!("authenticatorGetAssertion (0x02)");
    println!("- rpid_hash({:02})                          = {:?}", ass.rpid_hash.len(),util::to_hex_str(&ass.rpid_hash));
    println!("- flags_user_present_result               = {:?}", ass.flags_user_present_result);
    println!("- flags_user_verified_result              = {:?}", ass.flags_user_verified_result);
    println!("- flags_attested_credential_data_included = {:?}", ass.flags_attested_credential_data_included);
    println!("- flags_extensiondata_included            = {:?}", ass.flags_extension_data_included);
    println!("- sign_count                              = {:?}", ass.sign_count);
    println!("- aaguid({:02})                              = {:?}", ass.aaguid.len(),util::to_hex_str(&ass.aaguid));
    println!("- number_of_credentials                   = {:?}", ass.number_of_credentials);
    println!("- signature({:02})                           = {:?}", ass.signature.len(),util::to_hex_str(&ass.signature));
    println!("- user_id({:02})                             = {:?}", ass.user_id.len(),util::to_hex_str(&ass.user_id));
    println!("- user_name                               = {:?}", ass.user_name);
    println!("- user_display_name                       = {:?}", ass.user_display_name);
    println!("- credential_id({:02})                       = {:?}", ass.credential_id.len(),util::to_hex_str(&ass.credential_id));
    */

    let result = get_assertion_with_pin_result::GetAssertionWithPinResult{
        number_of_credentials: ass.number_of_credentials,
    };
    Ok(result)
}

// cargo test -- --test-threads=1

#[cfg(test)]
mod tests {
    use super::*;
    use serde_cbor::Value;
    use num::NumCast;
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
        println!("- retries       = {:?}", retry);
        assert!(true);
    }

    #[test]
    fn test_client_pin_get_keyagreement() {
        let params = HidParam::get_default_params();
        let device = ctaphid::connect_device(&params,0xf1d0).unwrap();
        let cid = ctaphid::ctaphid_init(&device);

        let send_payload = client_pin_command::create_payload(client_pin_command::SubCommand::GetKeyAgreement).unwrap();
        let response_cbor = ctaphid::ctaphid_cbor(&device,&cid,&send_payload).unwrap();
        //println!("{}",util::to_hex_str(&send_payload));
    
        let key_agreement = client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor).unwrap();
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

        let _result = make_credential_with_pin_non_rk(&params,rpid,&challenge,pin);

        assert!(true);
    }

    #[test]
    fn test_get_assertion_with_pin() {
        // parameter
        let rpid = "test.com";
        let challenge = b"this is challenge".to_vec();
        let credential_id = hex::decode("2C33F87AEFEB4280E85D97C68BF5FDFE2BB4C9598809C7F20EA254681CF4B284F710732347DDAA892815872D039BB22AFFCB0C8ECC79A85D34CE642B8B6C3514").unwrap();
        let pin = "1234";

        let hid_params = HidParam::get_default_params();

        get_assertion_with_pin(&hid_params,rpid,&challenge,&credential_id,pin);

        assert!(true);
    }

    #[test]
    fn decrypt_token() {
        /*
        let client_data_hash = hex::decode("E61E2BD6C4612662960B159CD54CF8EFF1A998C89B3742519D11F85E0F5E7876").unwrap();
        let x = hex::decode("A0266D4E6277C9B06C45E549641DDC3A2AEBFC51689A851364F7A5083E8B10E0").unwrap();
        let y = hex::decode("0BC0D53545D4950B634FC849954B49F4082F9117226123FCFF9DB51F79095C44").unwrap();
        let mut pin_token_enc = hex::decode("9AE0EE7F17328F42202EC2D0320BB3E0").unwrap();
        let pin_auth_check = hex::decode("9AE0EE7F17328F42202EC2D0320BB3E0").unwrap();

        let mut key_agreement =  cose::CoseKey::default();
        key_agreement.key_type = 2;
        key_agreement.algorithm = -25;
        key_agreement.parameters.insert(NumCast::from(-1).unwrap(), Value::Integer(1));
        key_agreement.parameters.insert(NumCast::from(-2).unwrap(), Value::Bytes(x));
        key_agreement.parameters.insert(NumCast::from(-3).unwrap(), Value::Bytes(y));

        let shared_secret = ss::SharedSecret::new(&key_agreement).unwrap();

        // pintoken -> dec(pintoken)
        let pin_token_dec = shared_secret.decrypt_token(&mut pin_token_enc);

        let pin_auth = pin_token_dec.unwrap().auth(&client_data_hash);

        assert_eq!(pin_auth.to_vec(),pin_auth_check);
        */
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
        let send_payload = 
        {
            let mut params = make_credential_command::Params::new(rpid,challenge.to_vec(),[].to_vec());
            params.option_rk = false; // non rk
            params.option_uv = true;

            println!("- client_data_hash({:02})    = {:?}", params.client_data_hash.len(),util::to_hex_str(&params.client_data_hash));

            // create pin auth
            //let pin_auth = pin_token.unwrap().auth(&params.client_data_hash);

            params.pin_auth = pin_auth.to_vec();

            make_credential_command::create_payload(params)
        };

        let command = hex::encode(send_payload).to_uppercase();
        assert_eq!(command,check);
    }

    #[test]
    fn test_create_pin_auth() {
        let out_bytes = hex::decode("1A81CD600A1F6CF4BE5260FE3257B241").unwrap();
        let client_data_hash = hex::decode("E61E2BD6C4612662960B159CD54CF8EFF1A998C89B3742519D11F85E0F5E7876").unwrap();
        //println!("- out_bytes({:?})       = {:?}", out_bytes.len(), util::to_hex_str(&out_bytes));
        let check = "F0AC99D6AAD2E199AF9CF25F6568A6F5".to_string();

        let pin_token_dec = pintoken::PinToken(hmac::SigningKey::new(&digest::SHA256, &out_bytes));
        let pin_auth = pin_token_dec.auth(&client_data_hash);

        assert_eq!(check,hex::encode(pin_auth).to_uppercase());
    }

}
