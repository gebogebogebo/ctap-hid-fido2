use anyhow::Result;
use log::{debug, log_enabled, Level};

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
    println!("----- test-with-pin-rk start -----");
    let mut cfg = Cfg::init();
    if log_enabled!(Level::Debug) {
        cfg.enable_log = true;
    }

    let pin = "1234";

    if get_fidokey_devices().is_empty() {
        println!("Could not find any devices to test resident key creation with pin on!");

        // This should be an error
        return Ok(());
    }

    let device = FidoKeyHidFactory::create(&cfg)?;

    //
    // Builder Pattern Sample
    //
    discoverable_credentials(&device, "test-rk.com", pin)
        .unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    with_cred_blob_ex(&device, "test-rk-2.com", pin)
        .unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    //
    // Legacy Pattern Sample
    //
    legacy_discoverable_credentials(&device, "test-rk-legacy.com", pin)
        .unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    println!("----- test-with-pin-rk end -----");
    Ok(())
}

fn discoverable_credentials(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    println!("----- discoverable_credentials -----");

    println!("- Register");
    let challenge = verifier::create_challenge();
    let user_entity =
        PublicKeyCredentialUserEntity::new(Some(b"1111"), Some("gebo"), Some("GEBO GEBO"));

    let mut strbuf = StrBuf::new(20);
    println!(
        "{}",
        strbuf
            .append("- rpid", &rpid)
            .appenh("- challenge", &challenge)
            .append("- user_entity", &user_entity)
            .build()
    );

    let make_credential_args = MakeCredentialArgsBuilder::new(&rpid, &challenge)
        .pin(pin)
        .user_entity(&user_entity)
        .resident_key()
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

fn with_cred_blob_ex(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    println!("----- with cred blob extension -----");

    println!("- Register");
    let challenge = verifier::create_challenge();
    let user_entity = PublicKeyCredentialUserEntity::new(
        Some(b"9999"),
        Some("cred blob ex"),
        Some("CRED BLOB EXTENSION"),
    );
    let protect = Mext::CredProtect(Some(CredentialProtectionPolicy::UserVerificationRequired));
    let blob = Mext::CredBlob((Some("this is test".as_bytes().to_vec()), None));

    let mut strbuf = StrBuf::new(20);
    println!(
        "{}",
        strbuf
            .append("- rpid", &rpid)
            .appenh("- challenge", &challenge)
            .append("- user_entity", &user_entity)
            .build()
    );

    let make_credential_args = MakeCredentialArgsBuilder::new(&rpid, &challenge)
        .pin(pin)
        .user_entity(&user_entity)
        .resident_key()
        .extensions(&vec![protect, blob])
        .build();

    let attestation = device.make_credential_with_args(&make_credential_args)?;
    println!("-- Register Success");
    let find = attestation.extensions.iter().find(|it| {
        if let Mext::CredProtect(_) = it {
            true
        } else {
            false
        }
    });

    if let Some(Mext::CredProtect(cred_protect)) = find {
        println!("--- Cred Protect = {:?}", cred_protect.unwrap());
    } else {
        println!("--- Cred Protect Not Found");
    }

    let find = attestation.extensions.iter().find(|it| {
        if let Mext::CredBlob((_, _)) = it {
            true
        } else {
            false
        }
    });

    if let Some(Mext::CredBlob((_, is_cred_blob))) = find {
        println!("--- Cred Blob = {:?}", is_cred_blob.unwrap());
    } else {
        println!("--- Cred Blob Not Found");
    }
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
    let ext = Gext::CredBlob((Some(true), None));
    let get_assertion_args = GetAssertionArgsBuilder::new(&rpid, &challenge)
        .pin(pin)
        .extensions(&vec![ext])
        .build();

    let assertions = device.get_assertion_with_args(&get_assertion_args)?;
    println!("-- Authenticate Success");

    let find = assertions[0].extensions.iter().find(|it| {
        if let Gext::CredBlob((_, _)) = it {
            true
        } else {
            false
        }
    });
    if let Some(Gext::CredBlob((_, cred_blob))) = find {
        let val = cred_blob.clone().unwrap();
        println!("--- Cred Blob = {}", String::from_utf8(val).unwrap());
    } else {
        println!("--- Cred Blob Not Found");
    }

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

fn legacy_discoverable_credentials(device: &FidoKeyHid, rpid: &str, pin: &str) -> Result<()> {
    println!("----- legacy_discoverable_credentials -----");

    println!("- Register");
    let challenge = verifier::create_challenge();
    let user_entity =
        PublicKeyCredentialUserEntity::new(Some(b"1111"), Some("gebo"), Some("GEBO GEBO"));
    //let user_entity = PublicKeyCredentialUserEntity::new(Some(b"2222"),Some("gebo-2"),Some("GEBO GEBO-2"));

    let mut strbuf = StrBuf::new(20);
    println!(
        "{}",
        strbuf
            .append("- rpid", &rpid)
            .appenh("- challenge", &challenge)
            .append("- user_entity", &user_entity)
            .build()
    );

    let attestation = device.make_credential_rk(rpid, &challenge, Some(pin), &user_entity)?;

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
