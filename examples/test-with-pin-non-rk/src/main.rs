use anyhow::Result;
use ctap_hid_fido2::get_assertion_params::Extension as Gext;
use ctap_hid_fido2::make_credential_params::Extension as Mext;
use ctap_hid_fido2::str_buf::StrBuf;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::Key;

fn main() -> Result<()> {
    let key_auto = true;
    println!(
        "----- test-with-pin-non-rk start : key_auto = {:?} -----",
        key_auto
    );
    let key = if key_auto { Key::auto() } else { Key::get() };

    // parameter
    let hmac_make=false;
    let hmac_get=false;
    let rpid = "test.com";
    let pin = "1234";
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
            &key,
            rpid,
            &challenge,
            Some(pin),
            Some(&vec![ext]),
        )?
    }else{
        ctap_hid_fido2::make_credential(
            &key,
            rpid,
            &challenge,
            Some(pin),
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
            &key,
            rpid,
            &challenge,
            &verify_result.credential_id,
            Some(pin),
            Some(&vec![ext]),
        )?    
    }else{
        ctap_hid_fido2::get_assertion(
            &key,
            rpid,
            &challenge,
            &verify_result.credential_id,
            Some(pin),
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

    println!("----- test-with-pin-non-rk end -----");
    Ok(())
}
