use anyhow::Result;
use log::{
    Level,
    debug,
    log_enabled,
};

use ctap_hid_fido2::{
    FidoKeyHid,
    get_fidokey_devices,
    fidokey::{
        GetAssertionArgsBuilder,
        MakeCredentialArgsBuilder
    },
};
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::str_buf::StrBuf;
use ctap_hid_fido2::{verifier, Cfg};

fn main() -> Result<()> {
    env_logger::init();
    println!("----- test-with-pin-rk start -----");
    let mut cfg = Cfg::init();
    if log_enabled!(Level::Debug) {
        cfg.enable_log = true;
    }

    let rpid = "test-rk.com";
    let pin = "123456";

    let mut devices = get_fidokey_devices();

    if devices.is_empty() {
        println!("Could not find any devices to test key creation with pin on!");

        // This should be an error
        return Ok(());
    }

    let device_descriptor = devices.pop().unwrap();
    let device = FidoKeyHid::new(&vec![device_descriptor.param], &cfg).unwrap();

    builder_pattern_sample(&device, rpid, pin)?;

    legacy_pattern_sample(&device, rpid, pin)?;

    println!("----- test-with-pin-rk end -----");
    Ok(())
}

//
// Builder Pattern Sample
//
fn builder_pattern_sample(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    discoverable_credentials(device, rpid, pin).unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    Ok(())
}

fn discoverable_credentials(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    println!("----- discoverable_credentials -----");

    println!("- Register");
    let challenge = verifier::create_challenge();
    let rkparam =
        PublicKeyCredentialUserEntity::new(Some(b"1111"), Some("gebo"), Some("GEBO GEBO"));

    let mut strbuf = StrBuf::new(20);
    println!(
        "{}",
        strbuf
            .append("- rpid", &rpid)
            .appenh("- challenge", &challenge)
            .append("- rkparam", &rkparam)
            .build()
    );

    let make_credential_args = MakeCredentialArgsBuilder::new(&rpid, &challenge)
        .pin(pin)
        .rkparam(&rkparam)
        .build();

    let attestation = device.make_credential_with_args(&make_credential_args)?;
    println!("-- Register Success");
    debug!("Attestation");
    debug!("{}", attestation);

    println!("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        println!("-- Verify Attestation Success");
    } else {
        println!("-- ! Verify Attestation Failed");
    }

    println!("- Authenticate");
    let challenge = verifier::create_challenge();
    let get_assertion_args = GetAssertionArgsBuilder::new(&rpid, &challenge)
        .pin(pin)
        .build();

    let assertions = device.get_assertion_with_args(&get_assertion_args)?;
    println!("-- Authenticate Success");
    println!("-- Assertion Num = {:?}", assertions.len());
    for assertion in &assertions {
        debug!("- assertion = {}", assertion);
        println!("- user = {}", assertion.user);
    }

    println!("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_publickey_der,
        &challenge,
        &assertions[0],
    );
    if is_success {
        println!("-- Verify Assertion Success");
    } else {
        println!("-- ! Verify Assertion Failed");
    }

    Ok(())
}

//
// Legacy Pattern Sample
//
fn legacy_pattern_sample(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    legacy_discoverable_credentials(device, rpid, pin)
        .unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    Ok(())
}

fn legacy_discoverable_credentials(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    println!("----- legacy_discoverable_credentials -----");

    println!("- Register");
    let challenge = verifier::create_challenge();
    let rkparam =
        PublicKeyCredentialUserEntity::new(Some(b"1111"), Some("gebo"), Some("GEBO GEBO"));
    //let rkparam = PublicKeyCredentialUserEntity::new(Some(b"2222"),Some("gebo-2"),Some("GEBO GEBO-2"));

    let mut strbuf = StrBuf::new(20);
    println!(
        "{}",
        strbuf
            .append("- rpid", &rpid)
            .appenh("- challenge", &challenge)
            .append("- rkparam", &rkparam)
            .build()
    );

    let attestation = device.make_credential_rk(rpid, &challenge, Some(pin), &rkparam)?;

    println!("-- Register Success");
    debug!("Attestation");
    debug!("{}", attestation);

    println!("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        println!("-- Verify Attestation Success");
    } else {
        println!("-- ! Verify Attestation Failed");
    }

    println!("- Authenticate");
    let challenge = verifier::create_challenge();
    let assertions = device.get_assertions_rk(rpid, &challenge, Some(pin))?;

    println!("-- Authenticate Success");
    println!("-- Assertion Num = {:?}", assertions.len());
    for assertion in &assertions {
        //println!("- assertion = {}", assertion);
        println!("- user = {}", assertion.user);
    }

    println!("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_publickey_der,
        &challenge,
        &assertions[0],
    );
    if is_success {
        println!("-- Verify Assertion Success");
    } else {
        println!("-- ! Verify Assertion Failed");
    }

    Ok(())
}
