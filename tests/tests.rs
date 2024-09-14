//
// cargo test test_main -- --nocapture
//

use ctap_hid_fido2::*;
use fidokey::get_info::{InfoOption, InfoParam};
use fidokey::MakeCredentialArgsBuilder;
use anyhow::{anyhow, Result};

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
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    device.get_info().unwrap();
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
