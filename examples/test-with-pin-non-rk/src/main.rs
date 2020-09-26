use ctap_hid_fido2;
use ctap_hid_fido2::util;

fn main() {
    println!("----- test-with-pin-non-rk start -----");
    
    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let pin = "1234";

    println!("make_credential_with_pin_non_rk()");
    let cre_id = match ctap_hid_fido2::make_credential_with_pin_non_rk(
                                &ctap_hid_fido2::HidParam::get_default_params(),
                                rpid,
                                &challenge,
                                pin){
        Ok(result) => result.credential_id,
        Err(err) => {
            println!("- Register Error {:?}",err);
            return;
        }
    };
    println!("- Register Success!!");
    println!("- credential_id({:02})  = {:?}", cre_id.len(),util::to_hex_str(&cre_id));

    println!("get_assertion_with_pin()");
    let result = match ctap_hid_fido2::get_assertion_with_pin(
                                        &ctap_hid_fido2::HidParam::get_default_params(),
                                        rpid,
                                        &challenge,
                                        &cre_id,
                                        pin){
        Ok(result) => result,
        Err(err) => {
            println!("- Authenticate Error {:?}",err);
            return;
        }
    };
    println!("- Authenticate Success!!");
    println!("- number_of_credentials = {:?}",result.number_of_credentials);

    println!("----- test-with-pin-non-rk end -----");
}
