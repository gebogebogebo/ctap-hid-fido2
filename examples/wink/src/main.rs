use ctap_hid_fido2;
use ctap_hid_fido2::HidParam;

fn main() {
    println!("----- wink start -----");
    match ctap_hid_fido2::wink(&HidParam::get_default_params()) {
        Ok(_) => {},
        Err(e) => println!("error: {:?}", e),
    }    
    println!("----- wink end -----");
}
