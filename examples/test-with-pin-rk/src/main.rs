use ctap_hid_fido2;
use ctap_hid_fido2::make_credential_params;
use ctap_hid_fido2::util;

fn main() {
    println!("----- test-with-pin-rk start -----");

    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let pin = "1234";

    /*
    let mut rkparam = make_credential_params::RkParam::default();
    rkparam.user_id = b"11111".to_vec();
    rkparam.user_name = "gebo2".to_string();
    rkparam.user_display_name = "GEBO2".to_string();

    println!("make_credential()");
    let cre_id = match ctap_hid_fido2::make_credential_rk(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        pin,
        &rkparam
        ) {
        Ok(result) => result.credential_id,
        Err(err) => {
            println!("- Register Error {:?}", err);
            return;
        }
    };

    println!("- Register Success!!");
    println!(
        "- credential_id({:02}) = {:?}",
        cre_id.len(),
        util::to_hex_str(&cre_id)
    );
    */

    println!("get_assertion_rk()");
    let att = match ctap_hid_fido2::get_assertion_rk(
        &ctap_hid_fido2::HidParam::get_default_params(),
        rpid,
        &challenge,
        pin,
    ) {
        Ok(result) => result,
        Err(err) => {
            println!("- Authenticate Error {:?}", err);
            return;
        }
    };
    println!("- Authenticate Success!!");
    att.print("Assertion");

    println!("----- test-with-pin-rk end -----");
}
