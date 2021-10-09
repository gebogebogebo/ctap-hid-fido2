use ctap_hid_fido2;
use ctap_hid_fido2::Key;

fn main() {
    println!("----- wink start -----");
    match ctap_hid_fido2::wink(&Key::auto()) {
        Ok(_) => {},
        Err(e) => println!("error: {:?}", e),
    }

    match ctap_hid_fido2::wink(&Key::get()) {
        Ok(_) => {},
        Err(e) => println!("error: {:?}", e),
    }
    println!("----- wink end -----");
}
