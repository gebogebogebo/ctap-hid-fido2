use anyhow::Result;
use ctap_hid_fido2;
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;
use ctap_hid_fido2::HidParam;
use ctap_hid_fido2::make_credential_params::Extension;

fn main() -> Result<()> {
    println!("----- test-with-pin-non-rk start -----");

    // parameter
    let rpid = "test.com";
    let pin = "1234";
    let challenge = verifier::create_challenge();

    // Register
    println!("Register - make_credential()");
    println!("- rpid          = {:?}", rpid);
    println!(
        "- challenge({:02}) = {:?}",
        challenge.len(),
        util::to_hex_str(&challenge)
    );

    /*
    let att = ctap_hid_fido2::make_credential(
        &HidParam::get_default_params(),
        rpid,
        &challenge,
        Some(pin),
    )?;
    */

    // PEND
    let ext = Extension::HmacSecret(true);
    let att = ctap_hid_fido2::make_credential_with_options(
        &HidParam::get_default_params(),
        rpid,
        &challenge,
        Some(pin),
        Some(&vec![ext])
    )?;

    println!("- Register Success!!");
    println!("Attestation");
    println!("{}", att);

    println!("Verify");
    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);
    println!(
        "- is_success                   = {:?}",
        verify_result.is_success
    );
    println!(
        "- credential_id({:02})            = {:?}",
        verify_result.credential_id.len(),
        util::to_hex_str(&verify_result.credential_id)
    );
    println!(
        "- credential_publickey_der({:02}) = {:?}",
        verify_result.credential_publickey_der.len(),
        util::to_hex_str(&verify_result.credential_publickey_der)
    );
    println!("");

    // Authenticate
    println!("Authenticate - get_assertion_with_pin()");
    let challenge = verifier::create_challenge();
    println!(
        "- challenge({:02}) = {:?}",
        challenge.len(),
        util::to_hex_str(&challenge)
    );

    let ass = ctap_hid_fido2::get_assertion(
        &HidParam::get_default_params(),
        rpid,
        &challenge,
        &verify_result.credential_id,
        Some(pin),
    )?;
    println!("- Authenticate Success!!");
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
