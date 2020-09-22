extern crate ctap_hid_fido2;

fn main() {
    println!("wink - start");

    let hid_params = ctap_hid_fido2::HidParam::get_default_params();
    ctap_hid_fido2::wink(&hid_params);
    
    println!("wink - end");
}