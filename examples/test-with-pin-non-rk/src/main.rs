extern crate ctap_hid_fido2;
use ctap_hid_fido2::util;

fn main() {
    println!("----- test-with-pin-non-rk start -----");
    
    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    //let user_id = b"user".to_vec();
    //let user_name = "test user";
    let pin = "1234";

    let hid_params = ctap_hid_fido2::HidParam::get_default_params();

    println!("- make_credential_with_pin_non_rk");
    let cre_id = match ctap_hid_fido2::make_credential_with_pin_non_rk(&hid_params,rpid,&challenge,pin){
        Ok(n) => n,
        Err(err) => {
            println!("{:?}",err);
            return;
        }
    };

    println!("credential_id({:02})  = {:?}", cre_id.len(),util::to_hex_str(&cre_id));
    println!("");

    println!("- get_assertion_with_pin");
    ctap_hid_fido2::get_assertion_with_pin(&hid_params,rpid,&challenge,&cre_id,pin);
    println!("");

    println!("----- test-with-pin-non-rk end -----");
}
