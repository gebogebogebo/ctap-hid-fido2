fn main() {
    println!("----- Nitrokey GETVERSION start -----");
    if let Err(msg) = ctap_hid_fido2::nitro_get_version(&ctap_hid_fido2::HidParam::get_default_params()){
        println!("error: {:?}", msg);
    }
    println!("----- Nitrokey GETVERSION end -----");
}
