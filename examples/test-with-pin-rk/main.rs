use anyhow::Result;
use colored::Colorize;
use log::{debug, log_enabled, Level};
use std::cell::RefCell;

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

use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::str_buf::StrBuf;
use ctap_hid_fido2::{
    fidokey::{
        credential_management::credential_management_params::CredentialProtectionPolicy,
        AssertionExtension as Gext, CredentialExtension as Mext, GetAssertionArgsBuilder,
        MakeCredentialArgsBuilder,
    },
    get_fidokey_devices, verifier, Cfg, FidoKeyHid, FidoKeyHidFactory,
};

fn main() -> Result<()> {
    env_logger::init();
    print_section("----- test-with-pin-rk start -----");
    let mut cfg = Cfg::init();
    if log_enabled!(Level::Debug) {
        cfg.enable_log = true;
    }

    let pin = "1234";

    if get_fidokey_devices().is_empty() {
        print_error("Could not find any devices to test resident key creation with pin on!");

        // This should be an error
        return Ok(());
    }

    let device = FidoKeyHidFactory::create(&cfg)?;

    //
    // Builder Pattern Sample
    //
    discoverable_credentials(&device, "test-rk.com", pin)
        .unwrap_or_else(|err| print_error_with_count(&format!("Error => {}\n", err), true));

    with_cred_blob_ex(&device, "test-rk-2.com", pin)
        .unwrap_or_else(|err| print_error_with_count(&format!("Error => {}\n", err), true));

    //
    // Legacy Pattern Sample
    //
    legacy_discoverable_credentials(&device, "test-rk-legacy.com", pin)
        .unwrap_or_else(|err| print_error_with_count(&format!("Error => {}\n", err), true));

    print_test_summary();
    print_section("----- test-with-pin-rk end -----");
    Ok(())
}

fn discoverable_credentials(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    print_section("----- discoverable_credentials -----");

    print_step("- Register");
    let challenge = verifier::create_challenge();
    let user_entity =
        PublicKeyCredentialUserEntity::new(Some(b"1111"), Some("gebo"), Some("GEBO GEBO"));

    let mut strbuf = StrBuf::new(20);
    print_info(
        &strbuf
            .append("- rpid", &rpid)
            .appenh("- challenge", &challenge)
            .append("- user_entity", &user_entity)
            .build()
    );

    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .user_entity(&user_entity)
        .resident_key()
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
        .build();

    let assertions = device.get_assertion_with_args(&get_assertion_args)?;
    print_success("-- Authenticate Success");
    print_info(&format!("-- Assertion Num = {:?}", assertions.len()));
    for assertion in &assertions {
        debug!("- assertion = {}", assertion);
        print_info(&format!("- user = {}", assertion.user));
    }

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

fn with_cred_blob_ex(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    print_section("----- with cred blob extension -----");

    print_step("- Register");
    let challenge = verifier::create_challenge();
    let user_entity = PublicKeyCredentialUserEntity::new(
        Some(b"9999"),
        Some("cred blob ex"),
        Some("CRED BLOB EXTENSION"),
    );
    let protect = Mext::CredProtect(Some(CredentialProtectionPolicy::UserVerificationRequired));
    let blob = Mext::CredBlob((Some("this is test".as_bytes().to_vec()), None));

    let mut strbuf = StrBuf::new(20);
    print_info(
        &strbuf
            .append("- rpid", &rpid)
            .appenh("- challenge", &challenge)
            .append("- user_entity", &user_entity)
            .build()
    );

    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .user_entity(&user_entity)
        .resident_key()
        .extensions(&[protect, blob])
        .build();

    let attestation = device.make_credential_with_args(&make_credential_args)?;
    print_success("-- Register Success");
    let find = attestation.extensions.iter().find(|it| {
        if let Mext::CredProtect(_) = it {
            true
        } else {
            false
        }
    });

    if let Some(Mext::CredProtect(cred_protect)) = find {
        print_info(&format!("--- Cred Protect = {:?}", cred_protect.unwrap()));
    } else {
        print_error("--- Cred Protect Not Found");
    }

    let find = attestation.extensions.iter().find(|it| {
        if let Mext::CredBlob((_, _)) = it {
            true
        } else {
            false
        }
    });

    if let Some(Mext::CredBlob((_, is_cred_blob))) = find {
        print_info(&format!("--- Cred Blob = {:?}", is_cred_blob.unwrap()));
    } else {
        print_error("--- Cred Blob Not Found");
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
    let ext = Gext::CredBlob((Some(true), None));
    let get_assertion_args = GetAssertionArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .extensions(&[ext])
        .build();

    let assertions = device.get_assertion_with_args(&get_assertion_args)?;
    print_success("-- Authenticate Success");

    let find = assertions[0].extensions.iter().find(|it| {
        if let Gext::CredBlob((_, _)) = it {
            true
        } else {
            false
        }
    });
    if let Some(Gext::CredBlob((_, cred_blob))) = find {
        let val = cred_blob.clone().unwrap();
        print_info(&format!("--- Cred Blob = {}", String::from_utf8(val).unwrap()));
    } else {
        print_error("--- Cred Blob Not Found");
    }

    print_info(&format!("-- Assertion Num = {:?}", assertions.len()));
    for assertion in &assertions {
        debug!("- assertion = {}", assertion);
        print_info(&format!("- user = {}", assertion.user));
    }

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

fn legacy_discoverable_credentials(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    print_section("----- legacy_discoverable_credentials -----");

    print_step("- Register");
    let challenge = verifier::create_challenge();
    let user_entity =
        PublicKeyCredentialUserEntity::new(Some(b"1111"), Some("gebo"), Some("GEBO GEBO"));
    //let user_entity = PublicKeyCredentialUserEntity::new(Some(b"2222"),Some("gebo-2"),Some("GEBO GEBO-2"));

    let mut strbuf = StrBuf::new(20);
    print_info(
        &strbuf
            .append("- rpid", &rpid)
            .appenh("- challenge", &challenge)
            .append("- user_entity", &user_entity)
            .build()
    );

    let attestation = device.make_credential_rk(rpid, &challenge, Some(pin), &user_entity)?;

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
    let assertions = device.get_assertions_rk(rpid, &challenge, Some(pin))?;

    print_success("-- Authenticate Success");
    print_info(&format!("-- Assertion Num = {:?}", assertions.len()));
    for assertion in &assertions {
        //debug!("- assertion = {}", assertion);
        print_info(&format!("- user = {}", assertion.user));
    }

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
