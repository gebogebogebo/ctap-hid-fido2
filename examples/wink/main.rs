use ctap_hid_fido2;
use ctap_hid_fido2::Key;
use ctap_hid_fido2::Cfg;

fn main() {
    let mut cfg = Cfg::init();

    println!("----- wink start -----");
    match ctap_hid_fido2::wink(&cfg) {
        Ok(_) => {},
        Err(e) => println!("error: {:?}", e),
    }

    cfg.hid_params = Key::get();
    match ctap_hid_fido2::wink(&cfg) {
        Ok(_) => {},
        Err(e) => println!("error: {:?}", e),
    }
    println!("----- wink end -----");
}
