use anyhow::Result;
use colored::Colorize;
use log::{debug, log_enabled, Level};
use std::cell::RefCell;

use ctap_hid_fido2::{
    fidokey::{
        AssertionExtension as Gext, CredentialExtension as Mext, CredentialSupportedKeyType,
        GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
    },
    get_fidokey_devices, util, verifier, Cfg, FidoKeyHid, FidoKeyHidFactory,
};

// Test Results Counter
thread_local! {
    static TEST_RESULTS: RefCell<TestResults> = RefCell::new(TestResults::new());
}

struct TestResults {
    total: usize,
    success: usize,
    failure: usize,
}

impl TestResults {
    fn new() -> Self {
        Self {
            total: 0,
            success: 0,
            failure: 0,
        }
    }

    fn add_test_result(&mut self, success: bool) {
        self.total += 1;
        if success {
            self.success += 1;
        } else {
            self.failure += 1;
        }
    }
}

fn print_test_summary() {
    TEST_RESULTS.with(|results| {
        let results = results.borrow();
        println!();
        print_section("===== Test Summary =====");
        println!("Total Tests:   {}", results.total);
        println!("Success Tests: {}", results.success.to_string().green().bold());
        println!("Failed Tests:  {}", results.failure.to_string().red().bold());
    });
}

// Helper functions: For colored output
fn print_section(message: &str) {
    println!("{}", message.blue().bold());
}

fn print_step(message: &str) {
    println!("{}", message.cyan());
}

fn print_success(message: &str) {
    println!("{}", message.green());
    if message.contains("Verify") {
        TEST_RESULTS.with(|results| {
            results.borrow_mut().add_test_result(true);
        });
    }
}

fn print_error(message: &str) {
    println!("{}", message.red().bold());
    if message.contains("Verify") {
        TEST_RESULTS.with(|results| {
            results.borrow_mut().add_test_result(false);
        });
    }
}

fn print_error_with_count(message: &str, count_as_failure: bool) {
    println!("{}", message.red().bold());
    if message.contains("Verify") || count_as_failure {
        TEST_RESULTS.with(|results| {
            results.borrow_mut().add_test_result(false);
        });
    }
}

fn print_info(message: &str) {
    println!("{}", message.yellow());
}

fn main() -> Result<()> {
    env_logger::init();
    print_section("----- test-with-pin-non-rk start -----");
    let mut cfg = Cfg::init();
    if log_enabled!(Level::Debug) {
        cfg.enable_log = true;
    }

    let rpid = "test.com";
    let pin = "1234";

    if get_fidokey_devices().is_empty() {
        println!("Could not find any devices to test non-resident key creation with pin on!");

        // This should be an error
        return Ok(());
    }

    let device = FidoKeyHidFactory::create(&cfg)?;

    builder_pattern_sample(&device, rpid, pin)?;

    legacy_pattern_sample(&device, rpid, pin)?;

    print_test_summary();
    print_section("----- test-with-pin-non-rk end -----");
    Ok(())
}

//
// Builder Pattern Sample
//
fn builder_pattern_sample(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    non_discoverable_credentials(device, rpid, pin)
        .unwrap_or_else(|err| {
            print_error_with_count(&format!("Error => {}\n", err), true);
        });

    with_uv(device, rpid).unwrap_or_else(|err| {
            print_error_with_count(&format!("Error => {}\n", err), true);
        });

    with_key_types(device, rpid, pin, vec![CredentialSupportedKeyType::Ecdsa256])
        .unwrap_or_else(|err| {
            print_error_with_count(&format!("Error => {}\n", err), true);
        });

    with_key_types(device, rpid, pin, vec![CredentialSupportedKeyType::Ed25519])
        .unwrap_or_else(|err| {
            print_error_with_count(&format!("Error => {}\n", err), true);
        });

    with_key_types(device, rpid, pin, vec![CredentialSupportedKeyType::Ed25519, CredentialSupportedKeyType::Ecdsa256])
        .unwrap_or_else(|err| {
            print_error_with_count(&format!("Error => {}\n", err), true);
        });

    with_hmac(device, rpid, pin).unwrap_or_else(|err| {
            print_error_with_count(&format!("Error => {}\n", err), true);
        });

    with_large_blob_key(device, rpid, pin).unwrap_or_else(|err| {
            print_error_with_count(&format!("Error => {}\n", err), true);
        });

    with_min_pin_length_ex(device, rpid, pin).unwrap_or_else(|err| {
            print_error_with_count(&format!("Error => {}\n", err), true);
        });

    without_pin(device, rpid).unwrap_or_else(|err| {
            print_error_with_count(&format!("Error => {}\n", err), true);
        });

    Ok(())
}

fn non_discoverable_credentials(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    print_section("----- non_discoverable_credentials -----");

    print_step("- Register");
    let challenge = verifier::create_challenge();

    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .build();

    let attestation = device.make_credential_with_args(&make_credential_args)?;
    print_success("-- Register Success");
    debug!("Attestation");
    debug!("{}", attestation);

    print_step("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        print_success("-- Verify Attestation Success");
    } else {
        print_error("-- ! Verify Attestation Failed");
    }

    print_step("- Authenticate");
    let challenge = verifier::create_challenge();

    let get_assertion_args = GetAssertionArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .credential_id(&verify_result.credential_id)
        .build();

    let assertions = device.get_assertion_with_args(&get_assertion_args)?;
    print_success("-- Authenticate Success");
    debug!("Assertion");
    debug!("{}", assertions[0]);

    print_step("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_public_key,
        &challenge,
        &assertions[0],
    );
    if is_success {
        print_success("-- Verify Assertion Success");
    } else {
        print_error("-- ! Verify Assertion Failed");
    }

    println!();
    Ok(())
}

fn with_uv(device: &FidoKeyHid, rpid: &str) -> Result<()> {
    print_section("----- with_uv -----");

    print_step("- Register");
    let challenge = verifier::create_challenge();

    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge).build();

    let attestation = device.make_credential_with_args(&make_credential_args)?;
    print_success("-- Register Success");
    debug!("Attestation");
    debug!("{}", attestation);

    print_step("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        print_success("-- Verify Attestation Success");
    } else {
        print_error("-- ! Verify Attestation Failed");
    }

    print_step("- Authenticate");
    let challenge = verifier::create_challenge();

    let get_assertion_args = GetAssertionArgsBuilder::new(rpid, &challenge)
        .credential_id(&verify_result.credential_id)
        .build();

    let assertions = device.get_assertion_with_args(&get_assertion_args)?;
    print_success("-- Authenticate Success");
    debug!("Assertion");
    debug!("{}", assertions[0]);

    print_step("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_public_key,
        &challenge,
        &assertions[0],
    );
    if is_success {
        print_success("-- Verify Assertion Success");
    } else {
        print_error("-- ! Verify Assertion Failed");
    }

    println!();
    Ok(())
}

fn with_key_types(
    device: &FidoKeyHid,
    rpid: &str,
    pin: &str,
    key_types: Vec<CredentialSupportedKeyType>,
) -> Result<()> {
    print_section(&format!("----- with_key_type ({:?}) -----", key_types));

    print_step("- Register");
    let challenge = verifier::create_challenge();

    let mut builder = MakeCredentialArgsBuilder::new(rpid, &challenge).pin(pin);
    for key_type in key_types {
        builder = builder.key_type(key_type)
    }
    let make_credential_args = builder.build();

    let attestation = device.make_credential_with_args(&make_credential_args)?;
    print_success("-- Register Success");
    debug!("Attestation");
    debug!("{}", attestation);

    print_step("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        print_success("-- Verify Attestation Success");
    } else {
        print_error("-- ! Verify Attestation Failed");
    }

    print_step("- Authenticate");
    let challenge = verifier::create_challenge();

    let get_assertion_args = GetAssertionArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .credential_id(&verify_result.credential_id)
        .build();

    let assertions = device.get_assertion_with_args(&get_assertion_args)?;
    print_success("-- Authenticate Success");
    debug!("Assertion");
    debug!("{}", assertions[0]);

    print_step("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_public_key,
        &challenge,
        &assertions[0],
    );
    if is_success {
        print_success("-- Verify Assertion Success");
    } else {
        print_error("-- ! Verify Assertion Failed");
    }

    println!();
    Ok(())
}

fn with_hmac(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    print_section("----- with hmac -----");

    print_step("- Register");
    let challenge = verifier::create_challenge();
    let ext = Mext::HmacSecret(Some(true));

    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .extensions(&[ext])
        .build();

    let attestation = device.make_credential_with_args(&make_credential_args)?;
    print_success("-- Register Success");
    let find = attestation.extensions.iter().find(|it| {
        matches!(it, Mext::HmacSecret(_))
    });
    if let Some(Mext::HmacSecret(is_hmac_secret)) = find {
        print_info(&format!("--- HMAC Secret = {:?}", is_hmac_secret.unwrap()));
    } else {
        print_error("--- HMAC Secret Not Found");
    }

    debug!("Attestation");
    debug!("{}", attestation);

    print_step("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        print_success("-- Verify Attestation Success");
    } else {
        print_error("-- ! Verify Attestation Failed");
    }

    print_step("- Authenticate");
    let challenge = verifier::create_challenge();
    let ext = Gext::create_hmac_secret_from_string("this is test");

    let get_assertion_args = GetAssertionArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .credential_id(&verify_result.credential_id)
        .extensions(&[ext])
        .build();

    let assertions = device.get_assertion_with_args(&get_assertion_args)?;
    print_success("-- Authenticate Success");
    let find = assertions[0].extensions.iter().find(|it| {
        matches!(it, Gext::HmacSecret(_))
    });
    if let Some(Gext::HmacSecret(hmac_secret)) = find {
        print_info(&format!(
            "--- HMAC Secret = {}",
            util::to_hex_str(&hmac_secret.unwrap())
        ));
    } else {
        print_error("--- HMAC Secret Not Found");
    }
    debug!("Assertion");
    debug!("{}", assertions[0]);

    print_step("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_public_key,
        &challenge,
        &assertions[0],
    );
    if is_success {
        print_success("-- Verify Assertion Success");
    } else {
        print_error("-- ! Verify Assertion Failed");
    }

    println!();
    Ok(())
}

fn without_pin(device: &FidoKeyHid, rpid: &str) -> Result<()> {
    print_section("----- without pin -----");

    print_step("- Register");
    let challenge = verifier::create_challenge();

    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .without_pin_and_uv()
        .build();

    let attestation = device.make_credential_with_args(&make_credential_args)?;
    print_success("-- Register Success");
    debug!("Attestation");
    debug!("{}", attestation);

    print_step("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        print_success("-- Verify Attestation Success");
    } else {
        print_error("-- ! Verify Attestation Failed");
    }

    print_step("- Authenticate");
    let challenge = verifier::create_challenge();

    let get_assertion_args = GetAssertionArgsBuilder::new(rpid, &challenge)
        .credential_id(&verify_result.credential_id)
        .without_pin_and_uv()
        .build();

    let assertions = device.get_assertion_with_args(&get_assertion_args)?;
    print_success("-- Authenticate Success");
    debug!("Assertion");
    debug!("{}", assertions[0]);

    print_step("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_public_key,
        &challenge,
        &assertions[0],
    );
    if is_success {
        print_success("-- Verify Assertion Success");
    } else {
        print_error("-- ! Verify Assertion Failed");
    }

    println!();
    Ok(())
}

fn with_large_blob_key(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    print_section("----- with large_blob_key -----");

    print_step("- Register");
    let challenge = verifier::create_challenge();
    let ext = Mext::LargeBlobKey((Some(true), None));

    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .extensions(&[ext])
        .build();

    let attestation = device.make_credential_with_args(&make_credential_args)?;
    print_success("-- Register Success");
    let find = attestation.extensions.iter().find(|it| {
        matches!(it, Mext::LargeBlobKey((_, _)))
    });
    if let Some(Mext::LargeBlobKey((_, large_blob_key))) = find {
        print_info(&format!(
            "--- Large Blob Key = {}",
            util::to_hex_str(&large_blob_key.clone().unwrap())
        ));
    } else {
        print_error("--- Large Blob Key Not Found");
    }
    debug!("Attestation");
    debug!("{}", attestation);

    print_step("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        print_success("-- Verify Attestation Success");
    } else {
        print_error("-- ! Verify Attestation Failed");
    }

    print_step("- Authenticate");
    let challenge = verifier::create_challenge();
    let ext = Gext::LargeBlobKey((Some(true), None));

    let get_assertion_args = GetAssertionArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .credential_id(&verify_result.credential_id)
        .extensions(&[ext])
        .build();

    let assertions = device.get_assertion_with_args(&get_assertion_args)?;
    print_success("-- Authenticate Success");
    let find = assertions[0].extensions.iter().find(|it| {
        matches!(it, Gext::LargeBlobKey((_, _)))
    });
    if let Some(Gext::LargeBlobKey((_, large_blob_key))) = find {
        print_info(&format!(
            "--- Large Blob Key = {}",
            util::to_hex_str(&large_blob_key.clone().unwrap())
        ));
    } else {
        print_error("--- Large Blob Key Not Found");
    }
    debug!("Assertion");
    debug!("{}", assertions[0]);

    print_step("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_public_key,
        &challenge,
        &assertions[0],
    );
    if is_success {
        print_success("-- Verify Assertion Success");
    } else {
        print_error("-- ! Verify Assertion Failed");
    }

    println!();
    Ok(())
}

fn with_min_pin_length_ex(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    print_section("----- with Min Pin Length Extension -----");
    print_info("       - Get Current Min Pin Length");
    print_info(&format!("       - Need Set Config Min Pin Length RPIDs [{}]", rpid));

    print_step("- Register");
    let challenge = verifier::create_challenge();
    let ext = Mext::MinPinLength((Some(true), None));

    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .extensions(&[ext])
        .build();

    let attestation = device.make_credential_with_args(&make_credential_args)?;
    print_success("-- Register Success");
    let find = attestation.extensions.iter().find(|it| {
        matches!(it, Mext::MinPinLength((_, _)))
    });
    if let Some(Mext::MinPinLength((_, min_pin_length))) = find {
        print_info(&format!("--- Min Pin Length = {:?}", min_pin_length));
    } else {
        print_error("--- Min Pin Length Not Found");
    }
    debug!("Attestation");
    debug!("{}", attestation);

    println!();
    Ok(())
}

//
// Legacy Pattern Sample
//
fn legacy_pattern_sample(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    legacy_non_discoverable_credentials(device, rpid, pin)
        .unwrap_or_else(|err| {
            print_error_with_count(&format!("Error => {}\n", err), true);
        });

    legacy_with_key_type(device, rpid, pin, CredentialSupportedKeyType::Ecdsa256)
        .unwrap_or_else(|err| {
            print_error_with_count(&format!("Error => {}\n", err), true);
        });

    // Verify Assertion in Ed25519 is always false because it is not yet implemented
    legacy_with_key_type(device, rpid, pin, CredentialSupportedKeyType::Ed25519)
        .unwrap_or_else(|err| {
            print_error_with_count(&format!("Error => {}\n", err), true);
        });

    legacy_with_uv(device, rpid).unwrap_or_else(|err| {
            print_error_with_count(&format!("Error => {}\n", err), true);
        });

    Ok(())
}

fn legacy_non_discoverable_credentials(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    print_section("----- legacy_non_discoverable_credentials -----");

    print_step("- Register");
    let challenge = verifier::create_challenge();
    let attestation = device.make_credential(rpid, &challenge, Some(pin))?;

    print_success("-- Register Success");
    debug!("Attestation");
    debug!("{}", attestation);

    print_step("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        print_success("-- Verify Attestation Success");
    } else {
        print_error("-- ! Verify Attestation Failed");
    }

    print_step("- Authenticate");
    let challenge = verifier::create_challenge();
    let assertion =
        device.get_assertion(rpid, &challenge, &[verify_result.credential_id], Some(pin))?;
    print_success("-- Authenticate Success");
    debug!("Assertion");
    debug!("{}", assertion);

    print_step("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_public_key,
        &challenge,
        &assertion,
    );
    if is_success {
        print_success("-- Verify Assertion Success");
    } else {
        print_error("-- ! Verify Assertion Failed");
    }

    println!();
    Ok(())
}

fn legacy_with_key_type(
    device: &FidoKeyHid,
    rpid: &str,
    pin: &str,
    key_type: CredentialSupportedKeyType,
) -> Result<()> {
    print_section(&format!("----- legacy_with_key_type ({:?}) -----", key_type));

    print_step("- Register");
    let challenge = verifier::create_challenge();
    let attestation =
        device.make_credential_with_key_type(rpid, &challenge, Some(pin), Some(key_type))?;

    print_success("-- Register Success");
    debug!("Attestation");
    debug!("{}", attestation);

    print_step("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        print_success("-- Verify Attestation Success");
    } else {
        print_error("-- ! Verify Attestation Failed");
    }

    print_step("- Authenticate");
    let challenge = verifier::create_challenge();
    let assertion =
        device.get_assertion(rpid, &challenge, &[verify_result.credential_id], Some(pin))?;
    print_success("-- Authenticate Success");
    debug!("Assertion");
    debug!("{}", assertion);

    print_step("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_public_key,
        &challenge,
        &assertion,
    );
    if is_success {
        print_success("-- Verify Assertion Success");
    } else {
        print_error("-- ! Verify Assertion Failed");
    }

    println!();
    Ok(())
}

fn legacy_with_uv(device: &FidoKeyHid, rpid: &str) -> Result<()> {
    print_section("----- legacy_with_uv -----");

    print_step("- Register");
    let challenge = verifier::create_challenge();
    let attestation = device.make_credential(rpid, &challenge, None)?;

    print_success("-- Register Success");
    debug!("Attestation");
    debug!("{}", attestation);

    print_step("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        print_success("-- Verify Attestation Success");
    } else {
        print_error("-- ! Verify Attestation Failed");
    }

    print_step("- Authenticate");
    let challenge = verifier::create_challenge();
    let assertion = device.get_assertion(rpid, &challenge, &[verify_result.credential_id], None)?;
    print_success("-- Authenticate Success");
    debug!("Assertion");
    debug!("{}", assertion);

    print_step("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_public_key,
        &challenge,
        &assertion,
    );
    if is_success {
        print_success("-- Verify Assertion Success");
    } else {
        print_error("-- ! Verify Assertion Failed");
    }

    println!();
    Ok(())
}
