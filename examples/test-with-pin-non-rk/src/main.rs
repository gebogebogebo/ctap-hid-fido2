use ctap_hid_fido2;
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;

fn main() {
    println!("----- test-with-pin-non-rk start -----");

    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let pin = "1234";

    println!("make_credential()");
    println!("- rpid = {:?}", rpid);

    let att = match ctap_hid_fido2::make_credential(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        pin,
    ) {
        Ok(result) => result,
        Err(err) => {
            println!("- Register Error {:?}", err);
            return;
        }
    };

    println!("- Register Success!!");
    att.print("Attestation");

    let verify_result = verifier::verify_attestation(rpid, &challenge, &att);
    println!("- is_verify                = {:?}", verify_result.is_verify);
    println!(
        "- credential_id({:02})        = {:?}",
        verify_result.credential_id.len(),
        util::to_hex_str(&verify_result.credential_id)
    );
    println!(
        "- credential_publickey_pem = {:?}",
        verify_result.credential_publickey_pem
    );

    println!("get_assertion_with_pin()");
    let att = match ctap_hid_fido2::get_assertion(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        &verify_result.credential_id,
        pin,
    ) {
        Ok(result) => result,
        Err(err) => {
            println!("- Authenticate Error {:?}", err);
            return;
        }
    };
    println!("- Authenticate Success!!");
    println!("- sign_count = {:?}", att.sign_count);
    println!(
        "- signature({:02}) = {:?}",
        att.signature.len(),
        util::to_hex_str(&att.signature)
    );

    let is_verify = verifier::verify_assertion(
        rpid,
        &verify_result.credential_publickey_der,
        &challenge,
        &att,
    );
    println!("- is_verify                = {:?}", is_verify);

    println!("----- test-with-pin-non-rk end -----");
}
