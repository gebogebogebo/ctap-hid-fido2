fn main() {
    println!("----- Nitrokey GETVERSION start -----");
    let result = match ctap_hid_fido2::nitro_get_version(&ctap_hid_fido2::HidParam::get_default_params()){
        Ok(version) => println!("version = {}",version),
        Err(err) => println!("version = {}",err),
    };
    println!("----- Nitrokey GETVERSION end -----");

    println!("----- Nitrokey GETSTATUS start -----");
    let result = match ctap_hid_fido2::nitro_get_status(&ctap_hid_fido2::HidParam::get_default_params()){
        Ok(status) => println!("status = {}",status),
        Err(err) => println!("status = {}",err),
    };
    println!("----- Nitrokey GETSTATUS end -----");
    
}
