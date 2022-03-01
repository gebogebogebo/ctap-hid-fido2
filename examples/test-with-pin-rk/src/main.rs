use anyhow::Result;
use ctap_hid_fido2;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::Cfg;
use ctap_hid_fido2::Key;
use ctap_hid_fido2::str_buf::StrBuf;

fn main() -> Result<()> {
    let key_auto = true;
    println!(
        "----- test-with-pin-rk start : key_auto = {:?} -----",
        key_auto
    );
    let mut cfg = Cfg::init();
    //cfg.enable_log = true;
    cfg.hid_params = if key_auto { Key::auto() } else { Key::get() };

    with_pin(&cfg,"1234")?;

    /*
    // parameter
    let rpid = "ge.com";
    let pin = "1234";

    // Register
    let challenge = verifier::create_challenge();
    let rkparam = PublicKeyCredentialUserEntity::new(Some(b"1111"),Some("gebo"),Some("GEBO GEBO"));

    let mut strbuf = StrBuf::new(20);
    println!(
        "{}",
        strbuf
            .appent("Register - make_credential()")
            .append("- rpid", &rpid)
            .appenh("- challenge", &challenge)
            .append("- rkparam", &rkparam)
            .build()
    );

    let att = ctap_hid_fido2::make_credential_rk(
        &cfg,
        rpid,
        &challenge,
        Some(pin),
        &rkparam,
    )?;

    println!("Register Success!!");
    println!("{}", att);

    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);

    let mut strbuf = StrBuf::new(30);
    println!(
        "{}",
        strbuf
            .appent("Verify")
            .append("- is_success", &verify_result.is_success)
            .appenh("- credential_publickey_der", &verify_result.credential_publickey_der)
            .appenh("- credential_id", &verify_result.credential_id)
            .build()
    );

    // Authenticate
    println!("Authenticate - get_assertions_rk()");
    let challenge = verifier::create_challenge();
    let asss = ctap_hid_fido2::get_assertions_rk(
        &cfg,
        rpid,
        &challenge,
        Some(pin),
    )?;
    println!("Authenticate Success!!");

    println!("- Assertion Num = {:?}", asss.len());
    println!();
    for ass in asss {
        println!("assertion");
        println!("{}", ass);
    }
*/

    println!("----- test-with-pin-rk end -----");
    Ok(())
}

fn with_pin(cfg: &Cfg,pin: &str) -> Result<()> {
    // parameter
    let rpid = "ge.com";

    // Register
    let challenge = verifier::create_challenge();
    let rkparam = PublicKeyCredentialUserEntity::new(Some(b"1111"),Some("gebo"),Some("GEBO GEBO"));

    let mut strbuf = StrBuf::new(20);
    println!(
        "{}",
        strbuf
            .appent("Register - make_credential()")
            .append("- rpid", &rpid)
            .appenh("- challenge", &challenge)
            .append("- rkparam", &rkparam)
            .build()
    );

    let make_credential_args = ctap_hid_fido2::MakeCredentialArgsBuilder::new(&rpid, &challenge)
    .pin(pin)
    .rkparam(&rkparam)
    .build();

    let att = ctap_hid_fido2::make_credential_with_args(&cfg, &make_credential_args)?;

    println!("Register Success!!");
    println!("{}", att);

    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);

    let mut strbuf = StrBuf::new(30);
    println!(
        "{}",
        strbuf
            .appent("Verify")
            .append("- is_success", &verify_result.is_success)
            .appenh("- credential_publickey_der", &verify_result.credential_publickey_der)
            .appenh("- credential_id", &verify_result.credential_id)
            .build()
    );

    // Authenticate
    println!("Authenticate - get_assertions_rk()");
    let challenge = verifier::create_challenge();
    let get_assertion_args = ctap_hid_fido2::GetAssertionArgsBuilder::new(&rpid, &challenge)
    .pin(pin)
    .build();

    let asss = ctap_hid_fido2::get_assertion_with_args(cfg,&get_assertion_args)?;

    println!("Authenticate Success!!");

    println!("- Assertion Num = {:?}", asss.len());
    println!();
    for ass in asss {
        println!("assertion");
        println!("{}", ass);
    }

    Ok(())
}
