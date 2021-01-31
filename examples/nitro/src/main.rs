fn main() {

    println!("----- Nitrokey GETVERSION start -----");
    // get 4byte payload "2001" -> ver 2.0.0.1
    match ctap_hid_fido2::nitrokey::get_version(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(version) => println!("version = {}", version),
        Err(err) => println!("version = {}", err),
    };
    println!("----- Nitrokey GETVERSION end -----");

    println!("----- Nitrokey GETSTATUS start -----");
    match ctap_hid_fido2::nitrokey::get_status(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(status) => status.print("status"),
        Err(err) => println!("status = {}", err),
    };
    println!("----- Nitrokey GETSTATUS end -----");

    println!("----- Nitrokey GETRNG start -----");
    // get 8 byte rundom data
    match ctap_hid_fido2::nitrokey::get_rng(&ctap_hid_fido2::HidParam::get_default_params(), 8) {
        Ok(rng) => println!("rng = {}", rng),
        Err(err) => println!("rng = {}", err),
    };
    println!("----- Nitrokey GETRNG end -----");
}
