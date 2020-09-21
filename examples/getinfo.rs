extern crate ctap_hid_fido2;

// cargo run --example getinfo

fn main() {
    println!("getinfo - start");

    let result = ctap_hid_fido2::get_info().unwrap();

    for (key, value) in result {
        println!("{} / {}", key, value);
    }

    println!("getinfo - end");
}