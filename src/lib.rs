pub mod ctaphid;
pub mod get_info_command;
pub mod get_info_response;
pub mod make_credential_command;
pub mod make_credential_response;
pub mod get_assertion_command;
pub mod get_assertion_response;
pub mod client_pin_command;
pub mod client_pin_response;
pub mod util;
pub mod cose;
pub mod p256;
pub mod ss;
pub mod pintoken;

extern crate crypto as rust_crypto;

// cargo test -- --test-threads=1

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_hid_devices() {
        let devs = ctaphid::get_hid_devices();
        assert!(devs.len()>0);
    }
    
    #[test]
    fn wink() {
        let params = ctaphid::HidParam::get_default_params();
        let device = ctaphid::connect_device(params);
        let cid = ctaphid::ctaphid_init(&device);
        ctaphid::ctaphid_wink(&device,&cid);
    }

    #[test]
    fn get_info() {
        let params = ctaphid::HidParam::get_default_params();
        let device = ctaphid::connect_device(params);
        let cid = ctaphid::ctaphid_init(&device);

        let send_payload = get_info_command::create_payload();
        println!("{}",util::to_hex_str(&send_payload));

        let response_cbor = ctaphid::ctaphid_cbor(&device,&cid,&send_payload).unwrap();

        let info = get_info_response::parse_cbor(&response_cbor).unwrap();
        println!("authenticatorGetInfo (0x04)");
        println!("- versions      = {:?}", info.versions);
        println!("- extensions    = {:?}", info.extensions);
        println!("- aaguid({:?})    = {:?}", info.aaguid.len(),util::to_hex_str(&info.aaguid));
        println!("- options       = {:?}", info.options);
        println!("- max_msg_size  = {:?}", info.max_msg_size);
        println!("- pin_protocols = {:?}", info.pin_protocols);

        assert!(true);
    }

    #[test]
    fn client_pin_get_retries() {
        let params = ctaphid::HidParam::get_default_params();
        let device = ctaphid::connect_device(params);
        let cid = ctaphid::ctaphid_init(&device);

        let send_payload = client_pin_command::create_payload(client_pin_command::SubCommand::GetRetries).unwrap();
        println!("{}",util::to_hex_str(&send_payload));

        let response_cbor = ctaphid::ctaphid_cbor(&device,&cid,&send_payload).unwrap();

        let pin = client_pin_response::parse_cbor_client_pin_get_retries(&response_cbor).unwrap();
        println!("authenticatorClientPIN (0x06) - getRetries");
        println!("- retries       = {:?}", pin.retries);

        assert!(true);
    }

    #[test]
    fn client_pin_get_keyagreement() {
        let params = ctaphid::HidParam::get_default_params();
        let device = ctaphid::connect_device(params);
        let cid = ctaphid::ctaphid_init(&device);

        let send_payload = client_pin_command::create_payload(client_pin_command::SubCommand::GetKeyAgreement).unwrap();
        let response_cbor = ctaphid::ctaphid_cbor(&device,&cid,&send_payload).unwrap();
        //println!("{}",util::to_hex_str(&send_payload));
    
        let key_agreement = client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor).unwrap();
        key_agreement.print("authenticatorClientPIN (0x06) - getKeyAgreement");        

        assert!(true);
    }

    #[test]
    fn make_credential_with_pin_non_rk() {
        // parameter
        let pin = "1234";
        let challenge = b"this is challenge".to_vec();
        let user_id = b"12345".to_vec();
        let user_name = "test user";

        // init
        let params = ctaphid::HidParam::get_default_params();
        let device = ctaphid::connect_device(params);
        let cid = ctaphid::ctaphid_init(&device);

        // pin token
        let pin_token = get_pin_token(&device,&cid,pin.to_string());

        // create cmmand
        let send_payload = 
        {
            let mut params = make_credential_command::Params::new("test.com",challenge,user_id);
            params.user_name = user_name.to_string();
            //params.user_display_name = String::from("DispUser");
    
            // create pin auth
            let pin_auth = pin_token.unwrap().auth(&params.client_data_hash);
            println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));
            params.pin_auth = pin_auth.to_vec();
    
            make_credential_command::create_payload(params)
        };

        // send & response
        let response_cbor = ctaphid::ctaphid_cbor(&device,&cid,&send_payload).unwrap();

        let att = make_credential_response::parse_cbor(&response_cbor).unwrap();
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

        assert!(true);
    }

    #[test]
    fn get_assertion_with_pin() {
        // parameter
        let pin = "1234";
        let challenge = b"this is challenge".to_vec();
        let credential_id = hex::decode("2C33F87AEFEB4280E85D97C68BF5FDFE2BB4C9598809C7F20EA254681CF4B284F710732347DDAA892815872D039BB22AFFCB0C8ECC79A85D34CE642B8B6C3514").unwrap();

        // init
        let params = ctaphid::HidParam::get_default_params();
        let device = ctaphid::connect_device(params);
        let cid = ctaphid::ctaphid_init(&device);

        // pin token
        let pin_token = get_pin_token(&device,&cid,pin.to_string());

        // create cmmand
        let send_payload = 
        {
            let mut params = get_assertion_command::Params::new("test.com",challenge,credential_id);
            params.option_up=true;
            params.option_uv=true;

            // create pin auth
            let pin_auth = pin_token.unwrap().auth(&params.client_data_hash);
            println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));
            params.pin_auth = pin_auth.to_vec();

            get_assertion_command::create_payload(params)
        };

        // send & response
        let response_cbor = ctaphid::ctaphid_cbor(&device,&cid,&send_payload).unwrap();

        let ass = get_assertion_response::parse_cbor(&response_cbor).unwrap();
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

        assert!(true);
    }

}

pub fn get_pin_token(device:&hidapi::HidDevice,cid:&[u8],pin:String)->Option<pintoken::PinToken>
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
    
        // pintoken -> dec(pintoken)
        let pin_token_dec = shared_secret.decrypt_token(&mut pin_token_enc).unwrap();

        Some(pin_token_dec)
    }else{
        None
    }
}
