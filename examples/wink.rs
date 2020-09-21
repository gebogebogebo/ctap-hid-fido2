extern crate ctap_hid_fido2;

// cargo run --example wink

fn main() {
    println!("wink - start");

    ctap_hid_fido2::wink();

    println!("wink - end");
}