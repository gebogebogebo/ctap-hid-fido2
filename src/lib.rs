mod ctaphid;
mod get_info_command;
mod get_info_response;
mod make_credential_command;
mod make_credential_response;
mod get_assertion_command;
mod get_assertion_response;
mod client_pin_command;
mod client_pin_response;
pub mod util;
mod cose;
mod p256;
mod ss;
mod pintoken;

extern crate crypto as rust_crypto;

// cargo test -- --test-threads=1

#[cfg(test)]
mod tests {
    use super::*;
    use serde_cbor::Value;
    use num::NumCast;
    
    #[test]
    fn test_get_hid_devices() {
        get_hid_devices();        
        assert!(true);
    }
    
    #[test]
    fn test_wink() {
        let hid_params = HidParam::get_default_params();
        wink(&hid_params);
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
        let device = ctaphid::connect_device(&params,0xf1d0);
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
        let pin_auth = hex::decode("FF95E70BB8008BB1B0EE8296C0A16130").unwrap();

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

        let check = "01A7015820E61E2BD6C4612662960B159CD54CF8EFF1A998C89B3742519D11F85E0F5E787602A262696468746573742E636F6D646E616D656003A26269644100646E616D6561200481A263616C672664747970656A7075626C69632D6B657907A262726BF4627576F50850FF95E70BB8008BB1B0EE8296C0A161300901".to_string();
        let command = hex::encode(send_payload).to_string().to_uppercase();
        //hex::encode(data: T)
        assert_eq!(command,check);
    }

}

pub struct HidParam {
	pub vid: u16,
    pub pid: u16,
}

impl HidParam {
    pub fn get_default_params() -> Vec<HidParam>{
        vec![
            HidParam{vid:0x1050,pid:0x0402},        // yubikey
            HidParam{vid:0x1050,pid:0x0120},        // yubikey
            HidParam{vid:0x096E,pid:0x85D},         // biopass
            HidParam{vid:0x483,pid:0x0a2ca},        // solokey
        ]
    }
}

fn get_pin_token(device:&hidapi::HidDevice,cid:&[u8],pin:String)->Option<pintoken::PinToken>
{
    if pin.len() > 0 {
        let send_payload = client_pin_command::create_payload(client_pin_command::SubCommand::GetKeyAgreement).unwrap();
        let response_cbor = ctaphid::ctaphid_cbor(device,cid,&send_payload).unwrap();
    
        let key_agreement = client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor).unwrap();
        key_agreement.print("authenticatorClientPIN (0x06) - getKeyAgreement");        
    
        let shared_secret = ss::SharedSecret::new(&key_agreement).unwrap();
        shared_secret.public_key.print("SharedSecret  - Public Key");
        
        let pin_hash_enc = shared_secret.encrypt_pin(&pin).unwrap();
        println!("- PIN hash enc({:?})       = {:?}", pin_hash_enc.len(), util::to_hex_str(&pin_hash_enc));
    
        let send_payload = client_pin_command::create_payload_get_pin_token(&shared_secret.public_key,pin_hash_enc.to_vec());
        let response_cbor = ctaphid::ctaphid_cbor(&device,&cid,&send_payload).unwrap();
    
        // get pin_token (enc)
        let mut pin_token_enc = client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor).unwrap();
        println!("- pin_token_enc({:?})       = {:?}", pin_token_enc.len(), util::to_hex_str(&pin_token_enc));
    
        // pintoken -> dec(pintoken)
        let pin_token_dec = shared_secret.decrypt_token(&mut pin_token_enc).unwrap();
        //println!("- pin_token_dec({:?})       = {:?}", pin_token_dec.len(), util::to_hex_str(&pin_token_dec));

        Some(pin_token_dec)
    }else{
        None
    }
}

pub fn get_info(hid_params:&[HidParam])->Result<Vec<(String,String)>,String>{
    let device = ctaphid::connect_device(hid_params,0xf1d0);
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

pub fn wink(hid_params:&[HidParam]){
    let device = ctaphid::connect_device(hid_params,0xf1d0);
    let cid = ctaphid::ctaphid_init(&device);
    ctaphid::ctaphid_wink(&device,&cid);
}

pub fn get_hid_devices()->Vec<(String,HidParam)>{
    ctaphid::get_hid_devices(None)
}

pub fn get_fidokey_devices()->Vec<(String,HidParam)>{
    ctaphid::get_hid_devices(Some(0xf1d0))
}

pub fn get_pin_retries(hid_params:&[HidParam])->i32{
    let device = ctaphid::connect_device(hid_params,0xf1d0);
    let cid = ctaphid::ctaphid_init(&device);

    let send_payload = client_pin_command::create_payload(client_pin_command::SubCommand::GetRetries).unwrap();
    //println!("{}",util::to_hex_str(&send_payload));

    let response_cbor = ctaphid::ctaphid_cbor(&device,&cid,&send_payload).unwrap();

    let pin = client_pin_response::parse_cbor_client_pin_get_retries(&response_cbor).unwrap();
    //println!("authenticatorClientPIN (0x06) - getRetries");
    //println!("- retries       = {:?}", pin.retries);

    pin.retries
}

pub fn make_credential_with_pin_non_rk(hid_param:&[HidParam],rpid:&str,challenge:&[u8],pin:&str)->Result<Vec<u8>,String> {

    // init
    let device = ctaphid::connect_device(hid_param,0xf1d0);
    let cid = ctaphid::ctaphid_init(&device);

    // pin token
    let pin_token = get_pin_token(&device,&cid,pin.to_string());

    // create cmmand
    let send_payload = 
    {
        let mut params = make_credential_command::Params::new(rpid,challenge.to_vec(),[].to_vec());
        //params.user_name = user_name.to_string();
        //params.user_display_name = String::from("DispUser");
        params.option_rk = false; // non rk
        params.option_uv = true;

        println!("- client_data_hash({:02})    = {:?}", params.client_data_hash.len(),util::to_hex_str(&params.client_data_hash));

        // create pin auth
        let pin_auth = pin_token.unwrap().auth(&params.client_data_hash);
        //let pin_auth = hex::decode("FF95E70BB8008BB1B0EE8296C0A16130").unwrap();

        println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));
        params.pin_auth = pin_auth.to_vec();

        make_credential_command::create_payload(params)
    };
    println!("- make_credential({:02})    = {:?}", send_payload.len(),util::to_hex_str(&send_payload));

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

    Ok(att.credential_id)
}

pub fn get_assertion_with_pin(hid_param:&[HidParam],rpid:&str,challenge:&[u8],credential_id:&[u8],pin:&str) {

    // init
    let device = ctaphid::connect_device(hid_param,0xf1d0);
    let cid = ctaphid::ctaphid_init(&device);

    // pin token
    let pin_token = get_pin_token(&device,&cid,pin.to_string());

    // create cmmand
    let send_payload = 
    {
        let mut params = get_assertion_command::Params::new(rpid,challenge.to_vec(),credential_id.to_vec());
        params.option_up=true;
        params.option_uv=true;

        // create pin auth
        let pin_auth = pin_token.unwrap().auth(&params.client_data_hash);
        //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));
        params.pin_auth = pin_auth.to_vec();

        get_assertion_command::create_payload(params)
    };

    // send & response
    let response_cbor = ctaphid::ctaphid_cbor(&device,&cid,&send_payload).unwrap();

    let _ass = get_assertion_response::parse_cbor(&response_cbor).unwrap();
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
}
