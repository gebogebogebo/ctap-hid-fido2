//
// cargo test test_main -- --nocapture
//
// [Be sure to also run the following tests:]
// cargo run --example test-with-pin-non-rk
// cargo run --example test-with-pin-rk

use ctap_hid_fido2::*;
use fidokey::get_info::{InfoOption, InfoParam};
use fidokey::MakeCredentialArgsBuilder;
use anyhow::{anyhow, Result};

fn is_my_test_key() -> Result<bool> {
    let keys = ctap_hid_fido2::get_fidokey_devices();
    if keys.len() != 1 {
        return Err(anyhow!("Expected exactly 1 FIDO key device, found {}", keys.len()));
    }

    if keys[0].vid == 0x1050 && keys[0].pid == 0x0402 {
        println!("Yubikey Bio");
        return Ok(true);
    } else {
        println!("Unexpected key {}", keys[0].info);
        return Ok(false);
    }
}

fn do_test<F>(f: F) where F: FnOnce() -> Result<()> {
    println!("{}", std::any::type_name::<F>());

    match f() {
        Ok(()) => {
            println!("ok");
        }
        Err(e) => {
            println!("- {:?}", e);
        }
      };    
    println!("");
}

#[test]
fn test_main() {
    println!("<<< TEST START >>>");

    do_test(test_get_hid_devices);
    do_test(test_get_info);
    do_test(test_get_info_u2f);
    do_test(test_client_pin_get_retries);
    do_test(test_make_credential_with_pin_non_rk);
    do_test(test_make_credential_with_pin_non_rk_exclude_authenticator);
    do_test(test_credential_management_get_creds_metadata);
    do_test(test_credential_management_enumerate_rps);
    do_test(test_bio_enrollment_get_fingerprint_sensor_info);
    do_test(test_bio_enrollment_enumerate_enrollments);
    do_test(test_wink);
    
    println!("<<< TEST END >>>");
}

#[test]
fn test_get_hid_devices() -> Result<()> {
    get_hid_devices();
    return Ok(());
}

#[test]
fn test_wink() -> Result<()> {
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    device.wink().unwrap();
    Ok(())
}

#[test]
fn test_get_info() -> Result<()> {
    if is_my_test_key()? {
        let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
        let info = device.get_info()?;
        println!("- versions = {:?}", info.versions);
        assert_eq!(
            info.versions, 
            vec!["U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE", "FIDO_2_1"]
        );
        
        println!("- extensions = {:?}", info.extensions);
        assert_eq!(
            info.extensions,
            vec!["credProtect", "hmac-secret", "largeBlobKey", "credBlob", "minPinLength"]
        );
        
        let aaguid_hex = util::to_hex_str(&info.aaguid);
        println!("- aaguid = {}", aaguid_hex);
        assert_eq!(aaguid_hex, "D8522D9F575B486688A9BA99FA02F35B");
        
        println!("- options = {:?}", info.options);
        let expected_options = vec![
            ("rk".to_string(), true),
            ("up".to_string(), true),
            ("uv".to_string(), true),
            ("plat".to_string(), false),
            ("uvToken".to_string(), true),
            ("alwaysUv".to_string(), true),
            ("credMgmt".to_string(), true),
            ("authnrCfg".to_string(), true),
            ("bioEnroll".to_string(), true),
            ("clientPin".to_string(), true),
            ("largeBlobs".to_string(), true),
            ("pinUvAuthToken".to_string(), true),
            ("setMinPINLength".to_string(), true),
            ("makeCredUvNotRqd".to_string(), false),
            ("credentialMgmtPreview".to_string(), true),
            ("userVerificationMgmtPreview".to_string(), true),
        ];

        assert_eq!(info.options.len(), expected_options.len());
        for option in expected_options {
            assert!(info.options.contains(&option));
        }
        
        println!("- max_msg_size = {}", info.max_msg_size);
        assert_eq!(info.max_msg_size, 1200);
        
        println!("- pin_uv_auth_protocols = {:?}", info.pin_uv_auth_protocols);
        assert_eq!(info.pin_uv_auth_protocols, vec![2, 1]);
        
        println!("- max_credential_count_in_list = {}", info.max_credential_count_in_list);
        assert_eq!(info.max_credential_count_in_list, 8);
        
        println!("- max_credential_id_length = {}", info.max_credential_id_length);
        assert_eq!(info.max_credential_id_length, 128);
        
        println!("- transports = {:?}", info.transports);
        assert_eq!(info.transports, vec!["usb"]);
        
        println!("- algorithms = {:?}", info.algorithms);
        let expected_algorithms = vec![
            ("alg".to_string(), "-7".to_string()),
            ("type".to_string(), "public-key".to_string()),
            ("alg".to_string(), "-8".to_string()),
            ("type".to_string(), "public-key".to_string()),
        ];
        assert_eq!(info.algorithms.len(), expected_algorithms.len());
        for alg in expected_algorithms {
            assert!(info.algorithms.contains(&alg));
        }
        
        println!("- max_serialized_large_blob_array = {}", info.max_serialized_large_blob_array);
        assert_eq!(info.max_serialized_large_blob_array, 1024);
        
        println!("- force_pin_change = {}", info.force_pin_change);
        assert_eq!(info.force_pin_change, false);
        
        println!("- min_pin_length = {}", info.min_pin_length);
        assert_eq!(info.min_pin_length, 4);
        
        println!("- firmware_version = {}", info.firmware_version);
        assert_eq!(info.firmware_version, 328966);
        
        println!("- max_cred_blob_length = {}", info.max_cred_blob_length);
        assert_eq!(info.max_cred_blob_length, 32);
        
        println!("- max_rpids_for_set_min_pin_length = {}", info.max_rpids_for_set_min_pin_length);
        assert_eq!(info.max_rpids_for_set_min_pin_length, 1);
        
        println!("- preferred_platform_uv_attempts = {}", info.preferred_platform_uv_attempts);
        assert_eq!(info.preferred_platform_uv_attempts, 3);
        
        println!("- uv_modality = {}", info.uv_modality);
        assert_eq!(info.uv_modality, 2);
        
        println!("- remaining_discoverable_credentials = {}", info.remaining_discoverable_credentials);
        assert_eq!(info.remaining_discoverable_credentials, 15);
    } else {
        let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
        device.get_info()?;
    }
    
    Ok(())
}

#[test]
fn test_get_info_u2f() -> Result<()> {
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    match device.enable_info_param(&InfoParam::VersionsU2Fv2) {
        Ok(result) => {
            if !result {
                return Err(anyhow!("skipped"));
            }
        }
        Err(_) => assert!(false),
    };

    device.get_info_u2f().unwrap();
    Ok(())
}

#[test]
fn test_client_pin_get_retries() -> Result<()> {
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();

    let retry = device.get_pin_retries();    
    println!("- retries = {:?}", retry);

    let uv_retry = device.get_uv_retries();    
    println!("- uv retries = {:?}", uv_retry);

    if is_my_test_key()? {
        assert_eq!(retry.unwrap(), 8);
        assert_eq!(uv_retry.unwrap(), 3);
    }

    Ok(())
}

#[test]
fn test_make_credential_with_pin_non_rk() -> Result<()> {
    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let pin = "1234";

    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    let att = device.make_credential(rpid, &challenge, Some(pin)).unwrap();
    println!("Attestation");
    println!("{}", att);

    let ass = device
        .get_assertion(rpid, &challenge, &[att.credential_descriptor.id], Some(pin))
        .unwrap();
    println!("Assertion");
    println!("{}", ass);

    Ok(())
}

#[test]
fn test_make_credential_with_pin_non_rk_exclude_authenticator() -> Result<()> {
    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let pin = "1234";

    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();

    let make_credential_args = MakeCredentialArgsBuilder::new(&rpid, &challenge)
        .pin(pin)
        .build();

    let att = device
        .make_credential_with_args(&make_credential_args)
        .unwrap();

    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);
    assert!(verify_result.is_success);

    let make_credential_args = MakeCredentialArgsBuilder::new(&rpid, &challenge)
        .pin(pin)
        .exclude_authenticator(&verify_result.credential_id)
        .build();

    let result = device.make_credential_with_args(&make_credential_args);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn test_credential_management_get_creds_metadata() -> Result<()> {
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    match device.enable_info_param(&InfoParam::VersionsFido21Pre) {
        Ok(result) => {
            if !result {
                return Err(anyhow!("skipped"));
            }
        }
        Err(_) => assert!(false),
    };

    let pin = "1234";
    match device.credential_management_get_creds_metadata(Some(pin)) {
        Ok(_) => assert!(true),
        Err(_) => assert!(false),
    };
    Ok(())
}

#[test]
fn test_credential_management_enumerate_rps() -> Result<()> {
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    match device.enable_info_param(&InfoParam::VersionsFido21Pre) {
        Ok(result) => {
            if !result {
                return Err(anyhow!("skipped"));
            }
        }
        Err(_) => assert!(false),
    };

    let pin = "1234";
    match device.credential_management_enumerate_rps(Some(pin)) {
        Ok(_) => assert!(true),
        Err(_) => assert!(false),
    };
    Ok(())
}

#[test]
fn test_bio_enrollment_get_fingerprint_sensor_info() -> Result<()> {
    let mut skip = true;

    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();

    match device.enable_info_option(&InfoOption::UserVerificationMgmtPreview) {
        Ok(result) => {
            //println!("result = {:?}", result);
            if let Some(v) = result {
                //println!("some value = {}", v);
                if v {
                    skip = false
                };
            }
        }
        Err(_) => assert!(false),
    };

    // skip
    if skip {
        return Err(anyhow!("skipped"));
    };

    match device.bio_enrollment_get_fingerprint_sensor_info() {
        Ok(_) => assert!(true),
        Err(_) => assert!(false),
    };
    Ok(())
}

#[test]
fn test_bio_enrollment_enumerate_enrollments() -> Result<()> {
    let mut skip = true;

    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();

    match device.enable_info_option(&InfoOption::UserVerificationMgmtPreview) {
        Ok(result) => {
            if let Some(v) = result {
                if v {
                    skip = false
                };
            }
        }
        Err(_) => assert!(false),
    };

    if skip {
        return Err(anyhow!("skipped"));
    };

    let pin = "1234";
    match device.bio_enrollment_enumerate_enrollments(pin) {
        Ok(_) => assert!(true),
        Err(_) => assert!(false),
    };

    return Ok(())
}
