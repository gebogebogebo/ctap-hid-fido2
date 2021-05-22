use anyhow::Result;
use ctap_hid_fido2;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::HidParam;

fn main() -> Result<()> {
    println!("----- test-with-pin-rk start -----");

    // parameter
    let rpid = "ge.com";
    let pin = "1234";

    // Register
    println!("Register - make_credential()");
    let challenge = verifier::create_challenge();
    let rkparam = PublicKeyCredentialUserEntity::new(Some(b"1111"),Some("gebo"),Some("GEBO GEBO"));
    /*
    let rkparam = PublicKeyCredentialUserEntity::new(
        Some(b"1111"),
        Some("123456788901234567889012345678890123456789012345678901234567890"),
        Some("123456788901234567889012345678890123456789012345678901234567890")
    );
    */

    println!("- rpid          = {:?}", rpid);
    println!(
        "- challenge({:02}) = {:?}",
        challenge.len(),
        util::to_hex_str(&challenge)
    );
    println!("- rkparam       = {}", rkparam);

    let att = ctap_hid_fido2::make_credential_rk(
        &HidParam::get_default_params(),
        rpid,
        &challenge,
        Some(pin),
        &rkparam,
    )?;

    println!("- Register Success!!");
    println!("{}", att);

    println!("Verify");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);
    println!(
        "- is_success                   = {:?}",
        verify_result.is_success
    );
    println!(
        "- credential_publickey_der({:02}) = {:?}",
        verify_result.credential_publickey_der.len(),
        util::to_hex_str(&verify_result.credential_publickey_der)
    );
    println!(
        "- credential_id({:02}) = {:?}",
        verify_result.credential_id.len(),
        util::to_hex_str(&verify_result.credential_id)
    );

    // Authenticate
    println!("Authenticate - get_assertions_rk()");
    let challenge = verifier::create_challenge();
    let asss = ctap_hid_fido2::get_assertions_rk(
        &HidParam::get_default_params(),
        rpid,
        &challenge,
        Some(pin),
    )?;
    println!("Authenticate Success!!");

    println!("- Assertion Num = {:?}", asss.len());
    for ass in asss {
        println!("- assertion = {}", ass);
        println!("- user = {}", ass.user);
    }

    println!("----- test-with-pin-rk end -----");
    Ok(())
}
