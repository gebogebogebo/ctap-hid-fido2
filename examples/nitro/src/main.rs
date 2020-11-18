fn main() {
    println!("----- Nitrokey GETVERSION start -----");
    // get 4byte payload "2001" -> ver 2.0.0.1
    match ctap_hid_fido2::nitro_get_version(&ctap_hid_fido2::HidParam::get_default_params()){
        Ok(version) => println!("version = {}",version),
        Err(err) => println!("version = {}",err),
    };
    println!("----- Nitrokey GETVERSION end -----");

    println!("----- Nitrokey GETSTATUS start -----");
    // get 8byte payload
    match ctap_hid_fido2::nitro_get_status(&ctap_hid_fido2::HidParam::get_default_params()){
        Ok(status) => status.print("status"),
        Err(err) => println!("status = {}",err),
    };
    println!("----- Nitrokey GETSTATUS end -----");

    println!("----- Nitrokey GETRNG start -----");
    // get ｘ byte rundom data
    match ctap_hid_fido2::nitro_get_rng(&ctap_hid_fido2::HidParam::get_default_params(),8){
        Ok(rng) => println!("rng = {}",rng),
        Err(err) => println!("rng = {}",err),
    };
    println!("----- Nitrokey GETRNG end -----");
    
}
