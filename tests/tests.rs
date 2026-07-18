//
// cargo test test_main -- --nocapture --test-threads=1
//
// This runs the suite twice against the connected device: once negotiated to
// PIN/UV Auth Protocol One, once to Protocol Two (skipping the Protocol Two
// run for any test if the device doesn't support it). `--test-threads=1` is
// required so the two runs don't contend for the single physical HID device.
//
// To run just one protocol version:
// cargo test test_main_pin_protocol_one -- --nocapture
// cargo test test_main_pin_protocol_two -- --nocapture
//
// [Be sure to also run the following tests:]
// cargo run --example test-with-pin-non-rk
// cargo run --example test-with-pin-rk

use anyhow::{anyhow, Result};
use ctap_hid_fido2::*;
use fidokey::get_info::{InfoOption, InfoParam};
use fidokey::MakeCredentialArgsBuilder;

fn is_my_test_key() -> Result<bool> {
    let keys = ctap_hid_fido2::get_fidokey_devices();
    if keys.len() != 1 {
        return Err(anyhow!(
            "Expected exactly 1 FIDO key device, found {}",
            keys.len()
        ));
    }

    if keys[0].vid == 0x1050 && keys[0].pid == 0x0402 {
        println!("Yubikey Bio");
        Ok(true)
    } else {
        println!("Unexpected key {}", keys[0].info);
        Ok(false)
    }
}

/// Create a device negotiated to the given PIN/UV Auth Protocol version.
/// Returns an ("skipped: ...") Err for protocol 2 if the device doesn't advertise support for it.
fn create_device_with_pin_protocol(cfg: &Cfg, pin_protocol_version: u8) -> Result<FidoKeyHid> {
    let mut device = FidoKeyHidFactory::create(cfg)?;
    if pin_protocol_version == 2 && !device.set_pin_uv_auth_protocol_two()? {
        return Err(anyhow!(
            "skipped: device does not support PIN/UV Auth Protocol Two"
        ));
    }
    Ok(device)
}

fn do_test<F>(f: F)
where
    F: FnOnce() -> Result<()>,
{
    println!("{}", std::any::type_name::<F>());

    match f() {
        Ok(()) => {
            println!("ok");
        }
        Err(e) => {
            println!("- {:?}", e);
        }
    };
    println!();
}

fn run_all_tests(pin_protocol_version: u8) {
    println!("<<< TEST START (PIN/UV Auth Protocol {}) >>>", pin_protocol_version);

    do_test(test_get_hid_devices);
    do_test(test_keep_alive_msg_to_stderr_cfg);
    do_test(test_keep_alive_msg_to_stderr_propagates);
    do_test(test_get_info);
    do_test(test_get_info_u2f);
    do_test(|| test_client_pin_get_retries(pin_protocol_version));
    do_test(|| test_make_credential_with_pin_non_rk(pin_protocol_version));
    do_test(|| test_make_credential_with_pin_non_rk_exclude_authenticator(pin_protocol_version));
    do_test(|| test_credential_management_get_creds_metadata(pin_protocol_version));
    do_test(|| test_credential_management_enumerate_rps(pin_protocol_version));
    do_test(|| test_bio_enrollment_get_fingerprint_sensor_info(pin_protocol_version));
    do_test(|| test_bio_enrollment_enumerate_enrollments(pin_protocol_version));
    do_test(test_wink);

    println!("<<< TEST END (PIN/UV Auth Protocol {}) >>>", pin_protocol_version);
}

#[test]
fn test_main_pin_protocol_one() {
    run_all_tests(1);
}

#[test]
fn test_main_pin_protocol_two() {
    run_all_tests(2);
}

#[test]
fn test_get_hid_devices() -> Result<()> {
    get_hid_devices();
    Ok(())
}

#[test]
fn test_keep_alive_msg_to_stderr_cfg() -> Result<()> {
    assert!(!Cfg::init().keep_alive_msg_to_stderr);
    assert!(Cfg::init()
        .with_keep_alive_msg_to_stderr(true)
        .keep_alive_msg_to_stderr);
    assert!(!Cfg::init()
        .with_keep_alive_msg_to_stderr(false)
        .keep_alive_msg_to_stderr);
    Ok(())
}

#[test]
fn test_keep_alive_msg_to_stderr_propagates() -> Result<()> {
    let device =
        FidoKeyHidFactory::create(&Cfg::init().with_keep_alive_msg_to_stderr(true))?;
    assert!(device.keep_alive_msg_to_stderr);

    let device = FidoKeyHidFactory::create(&Cfg::init())?;
    assert!(!device.keep_alive_msg_to_stderr);
    Ok(())
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
            vec![
                "credProtect",
                "hmac-secret",
                "largeBlobKey",
                "credBlob",
                "minPinLength"
            ]
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

        println!(
            "- max_credential_count_in_list = {}",
            info.max_credential_count_in_list
        );
        assert_eq!(info.max_credential_count_in_list, 8);

        println!(
            "- max_credential_id_length = {}",
            info.max_credential_id_length
        );
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

        println!(
            "- max_serialized_large_blob_array = {}",
            info.max_serialized_large_blob_array
        );
        assert_eq!(info.max_serialized_large_blob_array, 1024);

        println!("- force_pin_change = {}", info.force_pin_change);
        assert!(!info.force_pin_change);

        println!("- min_pin_length = {}", info.min_pin_length);
        assert_eq!(info.min_pin_length, 4);

        println!("- firmware_version = {}", info.firmware_version);
        assert_eq!(info.firmware_version, 328966);

        println!("- max_cred_blob_length = {}", info.max_cred_blob_length);
        assert_eq!(info.max_cred_blob_length, 32);

        println!(
            "- max_rpids_for_set_min_pin_length = {}",
            info.max_rpids_for_set_min_pin_length
        );
        assert_eq!(info.max_rpids_for_set_min_pin_length, 1);

        println!(
            "- preferred_platform_uv_attempts = {}",
            info.preferred_platform_uv_attempts
        );
        assert_eq!(info.preferred_platform_uv_attempts, 3);

        println!("- uv_modality = {}", info.uv_modality);
        assert_eq!(info.uv_modality, 2);

        println!(
            "- remaining_discoverable_credentials = {}",
            info.remaining_discoverable_credentials
        );
        assert!(
            info.remaining_discoverable_credentials > 1,
            "remaining_discoverable_credentials must be greater than 1, got {}",
            info.remaining_discoverable_credentials
        );
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

fn test_client_pin_get_retries(pin_protocol_version: u8) -> Result<()> {
    let device = create_device_with_pin_protocol(&Cfg::init(), pin_protocol_version)?;

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

fn test_make_credential_with_pin_non_rk(pin_protocol_version: u8) -> Result<()> {
    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let pin = "1234";

    let device = create_device_with_pin_protocol(&Cfg::init(), pin_protocol_version)?;
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

fn test_make_credential_with_pin_non_rk_exclude_authenticator(
    pin_protocol_version: u8,
) -> Result<()> {
    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let pin = "1234";

    let device = create_device_with_pin_protocol(&Cfg::init(), pin_protocol_version)?;

    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .build();

    let att = device
        .make_credential_with_args(&make_credential_args)
        .unwrap();

    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);
    assert!(verify_result.is_success);

    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .exclude_authenticator(&verify_result.credential_id)
        .build();

    let result = device.make_credential_with_args(&make_credential_args);
    assert!(result.is_err());
    Ok(())
}

fn test_credential_management_get_creds_metadata(pin_protocol_version: u8) -> Result<()> {
    let device = create_device_with_pin_protocol(&Cfg::init(), pin_protocol_version)?;
    match device.enable_info_option(&InfoOption::CredMgmt) {
        Ok(result) => {
            if result != Some(true) {
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

fn test_credential_management_enumerate_rps(pin_protocol_version: u8) -> Result<()> {
    let mut cfg = Cfg::init();
    cfg.use_pre_credential_management = false;
    let device = create_device_with_pin_protocol(&cfg, pin_protocol_version)?;
    match device.enable_info_option(&InfoOption::CredMgmt) {
        Ok(result) => {
            if result != Some(true) {
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

fn test_bio_enrollment_get_fingerprint_sensor_info(pin_protocol_version: u8) -> Result<()> {
    let mut skip = true;

    let device = create_device_with_pin_protocol(&Cfg::init(), pin_protocol_version)?;

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

fn test_bio_enrollment_enumerate_enrollments(pin_protocol_version: u8) -> Result<()> {
    let mut skip = true;

    let device = create_device_with_pin_protocol(&Cfg::init(), pin_protocol_version)?;

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

    Ok(())
}
