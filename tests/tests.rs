//
// cargo test -- --test-threads=1
//

use ctap_hid_fido2::*;
/*
use FidoKeyHid;
use crate::get_pin_token;
use crate::HidParam;
use crate::ctaphid;
use crate::credential_management_command;
use crate::util;
*/

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


/*
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

    let pin_token_dec = pintoken::PinToken{
        signing_key : hmac::SigningKey::new(&digest::SHA256, &out_bytes),
        key : out_bytes.to_vec(),
    };
    let pin_auth = pin_token_dec.authenticate_v1(&client_data_hash);

    assert_eq!(check, hex::encode(pin_auth).to_uppercase());
}
*/
