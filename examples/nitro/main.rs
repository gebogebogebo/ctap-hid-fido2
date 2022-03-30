use ctap_hid_fido2::nitrokey;
use ctap_hid_fido2::Cfg;
use ctap_hid_fido2::Key;

fn main() {
    let key_auto = true;
    println!(
        "----- Nitrokey : key_auto = {:?} -----",
        key_auto
    );
    let mut cfg = Cfg::init();
    //cfg.enable_log = true;
    cfg.hid_params = if key_auto { Key::auto() } else { Key::get() };

    println!("----- Nitrokey GETVERSION start -----");
    // get 4byte payload "2001" -> ver 2.0.0.1
    match nitrokey::get_version(&cfg) {
        Ok(version) => println!("version = {}", version),
        Err(err) => println!("version = {}", err),
    };
    println!("----- Nitrokey GETVERSION end -----");

    println!("----- Nitrokey GETSTATUS start -----");
    match nitrokey::get_status(&cfg) {
        Ok(status) => status.print("status"),
        Err(err) => println!("status = {}", err),
    };
    println!("----- Nitrokey GETSTATUS end -----");

    println!("----- Nitrokey GETRNG start -----");
    // get 8 byte rundom data
    match nitrokey::get_rng(&cfg, 8) {
        Ok(rng) => println!("rng = {}", rng),
        Err(err) => println!("rng = {}", err),
    };
    println!("----- Nitrokey GETRNG end -----");
}
