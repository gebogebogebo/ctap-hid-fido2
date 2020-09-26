extern crate ctap_hid_fido2;

fn main() {
    println!("----- wink start -----");
    println!("");

    let hid_params = ctap_hid_fido2::HidParam::get_default_params();
    //ctap_hid_fido2::wink(&hid_params);
    
    let result = match ctap_hid_fido2::wink(&hid_params) {
        Ok(()) => (),
        Err(error) => {
            println!("error: {:?}", error);
            return;
        },
    };    

    println!("----- wink end -----");
}