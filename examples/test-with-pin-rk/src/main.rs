use ctap_hid_fido2;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::util;
use ctap_hid_fido2::verifier;

fn main() {
    println!("----- test-with-pin-rk start -----");

    // parameter
    let rpid = "ge.com";
    let pin = "1234";

    let challenge = verifier::create_challenge();

    let mut rkparam = PublicKeyCredentialUserEntity::default();
    rkparam.id = b"11111".to_vec();
    rkparam.name = "gebo".to_string();
    rkparam.display_name = "GEBO GEBO".to_string();

    println!("Register - make_credential()");
    println!("- rpid          = {:?}", rpid);
    println!(
        "- challenge({:02}) = {:?}",
        challenge.len(),
        util::to_hex_str(&challenge)
    );
    println!("- rkparam       = {}", rkparam);

    let att = match ctap_hid_fido2::make_credential_rk(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        Some(pin),
        &rkparam
        ) {
        Ok(result) => result,
        Err(e) => {
            println!("- error {:?}", e);
            return;
        }
    };

    println!("- Register Success!!");
    println!("{}",att);

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
        println!("- assertion = {}",ass);
        println!("- user = {}",ass.user);
    }

    println!("----- test-with-pin-rk end -----");
}
