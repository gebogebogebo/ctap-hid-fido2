use anyhow::Result;
use ctap_hid_fido2::get_assertion_params::Extension as Gext;
use ctap_hid_fido2::make_credential_params::Extension as Mext;
use ctap_hid_fido2::str_buf::StrBuf;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::Cfg;
use ctap_hid_fido2::Key;
use ctap_hid_fido2::make_credential_params::CredentialSupportedKeyType;

fn main() -> Result<()> {
    let key_auto = true;
    println!(
        "----- test-with-pin-non-rk start : key_auto = {:?} -----",
        key_auto
    );
    let mut cfg = Cfg::init();
    //cfg.enable_log = true;
    cfg.hid_params = if key_auto { Key::auto() } else { Key::get() };

    let pin = "1234";

    // with pin
    with_pin(&cfg, pin)?;

    // with key type
    with_key_type(&cfg, pin)?;

    // with HMAC extensions
    with_hmac(&cfg, pin)?;

    /*
    // parameter
    let hmac_make=true;
    let hmac_get=true;
    let rpid = "test.com";
    let pin = Some("1234");
    //let pin = None;
    let challenge = verifier::create_challenge();


    // Register
    let mut strbuf = StrBuf::new(30);
    println!(
        "{}",
        strbuf
            .appent("Register - make_credential()")
            .append("- rpid", &rpid)
            .appenh("- challenge", &challenge)
            .append("- hmac-secret", &hmac_make)
            .build()
    );

    let att = if hmac_make{
        // with extensions
        let ext = Mext::HmacSecret(Some(true));
        ctap_hid_fido2::make_credential_with_extensions(
            &cfg,
            rpid,
            &challenge,
            pin,
            Some(&vec![ext]),
        )?
    }else{
        ctap_hid_fido2::make_credential(
            &cfg,
            rpid,
            &challenge,
            pin
        )?
    };


    println!("!! Register Success !!");
    println!("Attestation");
    println!("{}", att);

    println!("Verify");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);

    let mut strbuf = StrBuf::new(30);
    println!(
        "{}",
        strbuf
            .append("- is_success", &verify_result.is_success)
            .appenh("- credential_id", &verify_result.credential_id)
            .build()
    );

    // Authenticate
    let challenge = verifier::create_challenge();
    let mut strbuf = StrBuf::new(30);
    println!(
        "{}",
        strbuf
            .appent("Authenticate - get_assertion_with_pin()")
            .appenh("- challenge", &challenge)
            .append("- hmac-secret", &hmac_get)
            .build()
    );


    let ass = if hmac_get{
        let ext = Gext::create_hmac_secret_from_string("this is test");
        ctap_hid_fido2::get_assertion_with_extensios(
            &cfg,
            rpid,
            &challenge,
            &verify_result.credential_id,
            pin,
            Some(&vec![ext]),
        )?
    }else{
        ctap_hid_fido2::get_assertion(
            &cfg,
            rpid,
            &challenge,
            &verify_result.credential_id,
            pin,
        )?
    };

    println!("!! Authenticate Success !!");
    println!("Assertion");
    println!("{}", ass);

    println!("Verify");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_publickey_der,
        &challenge,
        &ass,
    );
    println!("- is_success = {:?}", is_success);
    */

    println!("----- test-with-pin-non-rk end -----");
    Ok(())
}

fn with_pin(cfg: &Cfg,pin: &str) -> Result<()> {
    println!("----- with pin -----");
    let rpid = "test.com";
    let challenge = verifier::create_challenge();

    let mut strbuf = StrBuf::new(30);
    println!(
        "{}",
        strbuf
            .appent("Register - with pin")
            .append("- rpid", &rpid)
            .appenh("- challenge", &challenge)
            .build()
    );

    let make_credential_args = ctap_hid_fido2::MakeCredentialArgsBuilder::new(&rpid, &challenge)
    .pin(pin)
    .build();

    let att = ctap_hid_fido2::make_credential_with_args(&cfg, &make_credential_args)?;

    println!("!! Register Success !!");
    //println!("Attestation");
    //println!("{}", att);

    println!("Verify");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);

    let mut strbuf = StrBuf::new(30);
    println!(
        "{}",
        strbuf
            .append("- is_success", &verify_result.is_success)
            .appenh("- credential_id", &verify_result.credential_id)
            .build()
    );

    // Authenticate
    let challenge = verifier::create_challenge();
    let mut strbuf = StrBuf::new(30);
    println!(
        "{}",
        strbuf
            .appent("Authenticate - with pin")
            .appenh("- challenge", &challenge)
            .build()
    );

    let get_assertion_args = ctap_hid_fido2::GetAssertionArgsBuilder::new(&rpid, &challenge)
    .pin(pin)
    .credential_id(&verify_result.credential_id)
    .build();

    let ass = ctap_hid_fido2::get_assertion_with_args(cfg,&get_assertion_args)?;

    println!("!! Authenticate Success !!");
    //println!("Assertion");
    //println!("{}", ass);

    println!("Verify");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_publickey_der,
        &challenge,
        &ass,
    );
    println!("- is_success = {:?}", is_success);

    Ok(())
}

fn with_hmac(cfg: &Cfg,pin: &str) -> Result<()> {
    println!("----- with hmac -----");
    let rpid = "test.com";
    let challenge = verifier::create_challenge();
    let ext = Mext::HmacSecret(Some(true));

    let mut strbuf = StrBuf::new(30);
    println!(
        "{}",
        strbuf
            .appent("Register - with hmac")
            .append("- rpid", &rpid)
            .appenh("- challenge", &challenge)
            .build()
    );

    let make_credential_args = ctap_hid_fido2::MakeCredentialArgsBuilder::new(&rpid, &challenge)
    .pin(pin)
    .extensions(&vec![ext])
    .build();

    let att = ctap_hid_fido2::make_credential_with_args(&cfg, &make_credential_args)?;

    println!("!! Register Success !!");
    //println!("Attestation");
    //println!("{}", att);

    println!("Verify");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);

    let mut strbuf = StrBuf::new(30);
    println!(
        "{}",
        strbuf
            .append("- is_success", &verify_result.is_success)
            .appenh("- credential_id", &verify_result.credential_id)
            .build()
    );

    // Authenticate
    let challenge = verifier::create_challenge();
    let ext = Gext::create_hmac_secret_from_string("this is test");

    let mut strbuf = StrBuf::new(30);
    println!(
        "{}",
        strbuf
            .appent("Authenticate - with hmac")
            .appenh("- challenge", &challenge)
            .build()
    );

    let get_assertion_args = ctap_hid_fido2::GetAssertionArgsBuilder::new(&rpid, &challenge)
    .pin(pin)
    .credential_id(&verify_result.credential_id)
    .extensions(&vec![ext])
    .build();

    let ass = ctap_hid_fido2::get_assertion_with_args(cfg,&get_assertion_args)?;

    println!("!! Authenticate Success !!");
    //println!("Assertion");
    //println!("{}", ass);

    println!("Verify");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_publickey_der,
        &challenge,
        &ass,
    );
    println!("- is_success = {:?}", is_success);

    Ok(())
}

fn with_key_type(cfg: &Cfg,pin: &str) -> Result<()> {
    println!("----- with key type -----");
    let rpid = "test.com";
    let challenge = verifier::create_challenge();

    let make_credential_args = ctap_hid_fido2::MakeCredentialArgsBuilder::new(&rpid, &challenge)
    .pin(pin)
    .key_type(CredentialSupportedKeyType::Ed25519)
    .build();

    let att = ctap_hid_fido2::make_credential_with_args(&cfg, &make_credential_args)?;

    println!("!! Register Success !!");
    //println!("Attestation");
    //println!("{}", att);

    println!("Verify");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);

    let mut strbuf = StrBuf::new(30);
    println!(
        "{}",
        strbuf
            .append("- is_success", &verify_result.is_success)
            .appenh("- credential_id", &verify_result.credential_id)
            .build()
    );

    // Authenticate
    let challenge = verifier::create_challenge();

    let get_assertion_args = ctap_hid_fido2::GetAssertionArgsBuilder::new(&rpid, &challenge)
    .pin(pin)
    .credential_id(&verify_result.credential_id)
    .build();

    let ass = ctap_hid_fido2::get_assertion_with_args(cfg,&get_assertion_args)?;

    println!("!! Authenticate Success !!");
    //println!("Assertion");
    //println!("{}", ass);

    println!("Verify");
    let is_success = verifier::verify_assertion(
        rpid,
        &verify_result.credential_publickey_der,
        &challenge,
        &ass,
    );
    println!("- is_success = {:?}", is_success);

    Ok(())
}
