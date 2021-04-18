//
// cargo test -- --test-threads=1
//

use ctap_hid_fido2::*;

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
fn test_get_info_u2f() {
    let hid_params = HidParam::get_default_params();
    get_info_u2f(&hid_params).unwrap();
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

#[test]
fn test_credential_management_get_creds_metadata() {
    match ctap_hid_fido2::enable_ctap_2_1(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => {
            if !result {
                // Skip
                return;
            }
        }
        Err(_) => assert!(false),
    };

    let pin = "1234";
    match ctap_hid_fido2::credential_management_get_creds_metadata(
        &ctap_hid_fido2::HidParam::get_default_params(),
        Some(pin),
    ) {
        Ok(_) => assert!(true),
        Err(_) => assert!(false),
    };
}

#[test]
fn test_credential_management_enumerate_rps() {
    match ctap_hid_fido2::enable_ctap_2_1(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => {
            if !result {
                // Skip
                return;
            }
        }
        Err(_) => assert!(false),
    };

    let pin = "1234";
    match ctap_hid_fido2::credential_management_enumerate_rps(
        &ctap_hid_fido2::HidParam::get_default_params(),
        Some(pin),
    ) {
        Ok(_) => assert!(true),
        Err(_) => assert!(false),
    };
}
