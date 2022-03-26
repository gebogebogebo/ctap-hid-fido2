use anyhow::Result;
use ctap_hid_fido2::get_assertion_params::Extension as Gext;
use ctap_hid_fido2::make_credential_params::CredentialSupportedKeyType;
use ctap_hid_fido2::make_credential_params::Extension as Mext;
use ctap_hid_fido2::MakeCredentialArgsBuilder;
use ctap_hid_fido2::{verifier, Cfg, Key};
//use ctap_hid_fido2::str_buf::StrBuf;

fn main() -> Result<()> {
    let key_auto = true;
    println!(
        "----- test-with-pin-non-rk start : key_auto = {:?} -----",
        key_auto
    );
    let mut cfg = Cfg::init();
    //cfg.enable_log = true;
    cfg.hid_params = if key_auto { Key::auto() } else { Key::get() };

    let rpid = "test.com";
    let pin = "1234";

    builder_pattern_sample(&cfg, rpid, pin)?;

    legacy_pattern_sample(&cfg, rpid, pin)?;

    println!("----- test-with-pin-non-rk end -----");
    Ok(())
}

//
// Builder Pattern Sample
//
fn builder_pattern_sample(cfg: &Cfg, rpid: &str, pin: &str) -> Result<()> {
    non_discoverable_credentials(cfg, rpid, pin)
        .unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    with_uv(cfg, rpid).unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    with_key_type(cfg, rpid, pin, CredentialSupportedKeyType::Ecdsa256)
        .unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    // Verify Assertion in Ed25519 is always false because it is not yet implemented
    with_key_type(cfg, rpid, pin, CredentialSupportedKeyType::Ed25519)
        .unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    with_hmac(cfg, rpid, pin).unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    without_pin(cfg, rpid).unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    Ok(())
}

fn non_discoverable_credentials(cfg: &Cfg, rpid: &str, pin: &str) -> Result<()> {
    println!("----- non_discoverable_credentials -----");

    println!("- Register");
    let challenge = verifier::create_challenge();

    let make_credential_args = MakeCredentialArgsBuilder::new(&rpid, &challenge)
        .pin(pin)
        .build();

    let attestation = ctap_hid_fido2::make_credential_with_args(&cfg, &make_credential_args)?;
    println!("-- Register Success");
    //println!("Attestation");
    //println!("{}", attestation);

    println!("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        println!("-- Verify Attestation Success");
    } else {
        println!("-- ! Verify Attestation Failed");
    }

    println!("- Authenticate");
    let challenge = verifier::create_challenge();

    let get_assertion_args = ctap_hid_fido2::GetAssertionArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .credential_id(&verify_result.credential_id)
        .build();

    let assertions = ctap_hid_fido2::get_assertion_with_args(cfg, &get_assertion_args)?;
    println!("-- Authenticate Success");
    //println!("Assertion");
    //println!("{}", assertions[0]);

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

    println!();
    Ok(())
}

fn with_uv(cfg: &Cfg, rpid: &str) -> Result<()> {
    println!("----- with_uv -----");

    println!("- Register");
    let challenge = verifier::create_challenge();

    let make_credential_args = MakeCredentialArgsBuilder::new(&rpid, &challenge).build();

    let attestation = ctap_hid_fido2::make_credential_with_args(&cfg, &make_credential_args)?;
    println!("-- Register Success");
    //println!("Attestation");
    //println!("{}", attestation);

    println!("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        println!("-- Verify Attestation Success");
    } else {
        println!("-- ! Verify Attestation Failed");
    }

    println!("- Authenticate");
    let challenge = verifier::create_challenge();

    let get_assertion_args = ctap_hid_fido2::GetAssertionArgsBuilder::new(rpid, &challenge)
        .credential_id(&verify_result.credential_id)
        .build();

    let assertions = ctap_hid_fido2::get_assertion_with_args(cfg, &get_assertion_args)?;
    println!("-- Authenticate Success");
    //println!("Assertion");
    //println!("{}", assertions[0]);

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

    println!();
    Ok(())
}

fn with_key_type(
    cfg: &Cfg,
    rpid: &str,
    pin: &str,
    key_type: CredentialSupportedKeyType,
) -> Result<()> {
    println!("----- with_key_type ({:?}) -----", key_type);

    println!("- Register");
    let challenge = verifier::create_challenge();

    let make_credential_args = MakeCredentialArgsBuilder::new(&rpid, &challenge)
        .pin(pin)
        .key_type(key_type)
        .build();

    let attestation = ctap_hid_fido2::make_credential_with_args(&cfg, &make_credential_args)?;
    println!("-- Register Success");
    //println!("Attestation");
    //println!("{}", attestation);

    println!("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        println!("-- Verify Attestation Success");
    } else {
        println!("-- ! Verify Attestation Failed");
    }

    println!("- Authenticate");
    let challenge = verifier::create_challenge();

    let get_assertion_args = ctap_hid_fido2::GetAssertionArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .credential_id(&verify_result.credential_id)
        .build();

    let assertions = ctap_hid_fido2::get_assertion_with_args(cfg, &get_assertion_args)?;
    println!("-- Authenticate Success");
    //println!("Assertion");
    //println!("{}", assertions[0]);

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

    println!();
    Ok(())
}

fn with_hmac(cfg: &Cfg, rpid: &str, pin: &str) -> Result<()> {
    println!("----- with hmac -----");

    println!("- Register");
    let challenge = verifier::create_challenge();
    let ext = Mext::HmacSecret(Some(true));

    let make_credential_args = MakeCredentialArgsBuilder::new(&rpid, &challenge)
        .pin(pin)
        .extensions(&vec![ext])
        .build();

    let attestation = ctap_hid_fido2::make_credential_with_args(&cfg, &make_credential_args)?;
    println!("-- Register Success");
    //println!("Attestation");
    //println!("{}", attestation);

    println!("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        println!("-- Verify Attestation Success");
    } else {
        println!("-- ! Verify Attestation Failed");
    }

    println!("- Authenticate");
    let challenge = verifier::create_challenge();
    let ext = Gext::create_hmac_secret_from_string("this is test");

    let get_assertion_args = ctap_hid_fido2::GetAssertionArgsBuilder::new(rpid, &challenge)
        .pin(pin)
        .credential_id(&verify_result.credential_id)
        .extensions(&vec![ext])
        .build();

    let assertions = ctap_hid_fido2::get_assertion_with_args(cfg, &get_assertion_args)?;
    println!("-- Authenticate Success");
    //println!("Assertion");
    //println!("{}", assertions[0]);

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

    println!();
    Ok(())
}

fn without_pin(cfg: &Cfg, rpid: &str) -> Result<()> {
    println!("----- without pin -----");

    println!("- Register");
    let challenge = verifier::create_challenge();

    let make_credential_args = MakeCredentialArgsBuilder::new(&rpid, &challenge)
        .without_pin_and_uv()
        .build();

    let attestation = ctap_hid_fido2::make_credential_with_args(&cfg, &make_credential_args)?;
    println!("-- Register Success");
    //println!("Attestation");
    //println!("{}", attestation);

    println!("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        println!("-- Verify Attestation Success");
    } else {
        println!("-- ! Verify Attestation Failed");
    }

    println!("- Authenticate");
    let challenge = verifier::create_challenge();

    let get_assertion_args = ctap_hid_fido2::GetAssertionArgsBuilder::new(rpid, &challenge)
        .credential_id(&verify_result.credential_id)
        .without_pin_and_uv()
        .build();

    let assertions = ctap_hid_fido2::get_assertion_with_args(cfg, &get_assertion_args)?;
    println!("-- Authenticate Success");
    //println!("Assertion");
    //println!("{}", assertions[0]);

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

    println!();
    Ok(())
}

//
// Legacy Pattern Sample
//
fn legacy_pattern_sample(cfg: &Cfg, rpid: &str, pin: &str) -> Result<()> {
    legacy_non_discoverable_credentials(cfg, rpid, pin)
        .unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    legacy_with_key_type(cfg, rpid, pin, CredentialSupportedKeyType::Ecdsa256)
        .unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    // Verify Assertion in Ed25519 is always false because it is not yet implemented
    legacy_with_key_type(cfg, rpid, pin, CredentialSupportedKeyType::Ed25519)
        .unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    Ok(())
}

fn legacy_non_discoverable_credentials(cfg: &Cfg, rpid: &str, pin: &str) -> Result<()> {
    println!("----- legacy_non_discoverable_credentials -----");

    println!("- Register");
    let challenge = verifier::create_challenge();
    let attestation = ctap_hid_fido2::make_credential(cfg, rpid, &challenge, Some(pin))?;

    println!("-- Register Success");
    //println!("Attestation");
    //println!("{}", attestation);

    println!("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        println!("-- Verify Attestation Success");
    } else {
        println!("-- ! Verify Attestation Failed");
    }

    println!("- Authenticate");
    let challenge = verifier::create_challenge();
    let assertion = ctap_hid_fido2::get_assertion(
        cfg,
        rpid,
        &challenge,
        &verify_result.credential_id,
        Some(pin),
    )?;
    println!("-- Authenticate Success");
    //println!("Assertion");
    //println!("{}", assertions[0]);

    println!("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_publickey_der,
        &challenge,
        &assertion,
    );
    if is_success {
        println!("-- Verify Assertion Success");
    } else {
        println!("-- ! Verify Assertion Failed");
    }

    println!();
    Ok(())
}

fn legacy_with_key_type(
    cfg: &Cfg,
    rpid: &str,
    pin: &str,
    key_type: CredentialSupportedKeyType,
) -> Result<()> {
    println!("----- legacy_with_key_type ({:?}) -----", key_type);

    println!("- Register");
    let challenge = verifier::create_challenge();
    let attestation = ctap_hid_fido2::make_credential_with_key_type(
        cfg,
        rpid,
        &challenge,
        Some(pin),
        Some(key_type),
    )?;

    println!("-- Register Success");
    //println!("Attestation");
    //println!("{}", attestation);

    println!("-- Verify Attestation");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if verify_result.is_success {
        println!("-- Verify Attestation Success");
    } else {
        println!("-- ! Verify Attestation Failed");
    }

    println!("- Authenticate");
    let challenge = verifier::create_challenge();
    let assertion = ctap_hid_fido2::get_assertion(
        cfg,
        rpid,
        &challenge,
        &verify_result.credential_id,
        Some(pin),
    )?;
    println!("-- Authenticate Success");
    //println!("Assertion");
    //println!("{}", assertions[0]);

    println!("-- Verify Assertion");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_publickey_der,
        &challenge,
        &assertion,
    );
    if is_success {
        println!("-- Verify Assertion Success");
    } else {
        println!("-- ! Verify Assertion Failed");
    }

    println!();
    Ok(())
}
