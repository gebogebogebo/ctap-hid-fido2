use ctap_hid_fido2;
use ctap_hid_fido2::make_credential_params;
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;

fn main() {
    println!("----- test-with-pin-rk start -----");

    // parameter
    let rpid = "ge.com";
    let pin = "1234";

    let challenge = verifier::create_challenge();

    let mut rkparam = make_credential_params::RkParam::default();
    rkparam.user_id = b"11111".to_vec();
    rkparam.user_name = "gebo".to_string();
    rkparam.user_display_name = "GEBO GEBO".to_string();

    println!("Register - make_credential()");
    println!("- rpid          = {:?}", rpid);
    println!(
        "- challenge({:02}) = {:?}",
        challenge.len(),
        util::to_hex_str(&challenge)
    );
    rkparam.print("RkParam");

    let att = match ctap_hid_fido2::make_credential_rk(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        Some(pin),
        &rkparam
        ) {
        Ok(result) => result,
        Err(err) => {
            println!("- Register Error {:?}", err);
            return;
        }
    };

    println!("- Register Success!!");
    att.print("Attestation");

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

    println!("Authenticate - get_assertions_rk()");

    let challenge = verifier::create_challenge();
    let asss = match ctap_hid_fido2::get_assertions_rk(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        Some(pin),
    ) {
        Ok(asss) => asss,
        Err(err) => {
            println!("- Authenticate Error {:?}", err);
            return;
        }
    };
    println!("Authenticate Success!!");

    println!("- Assertion Num = {:?}",asss.len());
    for ass in asss {
        ass.print("Assertion");
        println!(
            "- user_id({:02})       = {:?}",
            ass.user_id.len(),
            util::to_hex_str(&ass.user_id)
        );
    }

    println!("----- test-with-pin-rk end -----");
}
