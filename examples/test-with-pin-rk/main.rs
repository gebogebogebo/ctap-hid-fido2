use anyhow::Result;
use ctap_hid_fido2;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::str_buf::StrBuf;
use ctap_hid_fido2::{verifier, Cfg, Key};

fn main() -> Result<()> {
    let key_auto = true;
    println!(
        "----- test-with-pin-rk start : key_auto = {:?} -----",
        key_auto
    );
    let mut cfg = Cfg::init();
    //cfg.enable_log = true;
    cfg.hid_params = if key_auto { Key::auto() } else { Key::get() };

    let rpid = "test-rk.com";
    let pin = "1234";

    builder_pattern_sample(&cfg, rpid, pin)?;

    legacy_pattern_sample(&cfg, rpid, pin)?;

    println!("----- test-with-pin-rk end -----");
    Ok(())
}

//
// Builder Pattern Sample
//
fn builder_pattern_sample(cfg: &Cfg, rpid: &str, pin: &str) -> Result<()> {
    discoverable_credentials(cfg, rpid, pin).unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    Ok(())
}

fn discoverable_credentials(cfg: &Cfg, rpid: &str, pin: &str) -> Result<()> {
    println!("----- discoverable_credentials -----");

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

    let make_credential_args = ctap_hid_fido2::MakeCredentialArgsBuilder::new(&rpid, &challenge)
        .pin(pin)
        .rkparam(&rkparam)
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
    let get_assertion_args = ctap_hid_fido2::GetAssertionArgsBuilder::new(&rpid, &challenge)
        .pin(pin)
        .build();

    let assertions = ctap_hid_fido2::get_assertion_with_args(cfg, &get_assertion_args)?;
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

//
// Legacy Pattern Sample
//
fn legacy_pattern_sample(cfg: &Cfg, rpid: &str, pin: &str) -> Result<()> {
    legacy_discoverable_credentials(cfg, rpid, pin)
        .unwrap_or_else(|err| eprintln!("Error => {}\n", err));

    Ok(())
}

fn legacy_discoverable_credentials(cfg: &Cfg, rpid: &str, pin: &str) -> Result<()> {
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

    let attestation =
        ctap_hid_fido2::make_credential_rk(&cfg, rpid, &challenge, Some(pin), &rkparam)?;

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
    let assertions = ctap_hid_fido2::get_assertions_rk(&cfg, rpid, &challenge, Some(pin))?;

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
