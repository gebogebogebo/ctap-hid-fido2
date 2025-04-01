use anyhow::Result;
use ctap_hid_fido2::{fidokey::get_info::InfoOption, Cfg, FidoKeyHidFactory};
use std::process;

fn main() -> Result<()> {
    println!("----- test-config start -----");

    let devs = ctap_hid_fido2::get_fidokey_devices();
    if devs.len() != 1 {
        println!("Error: Exactly one FIDO device must be connected.");
        println!("Found: {} device(s)", devs.len());
        process::exit(1);
    }

    let dev = FidoKeyHidFactory::create(&Cfg::init())?;

    println!("Checking AlwaysUv setting...");
    match dev.enable_info_option(&InfoOption::AlwaysUv) {
        Ok(Some(always_uv)) => {
            println!("AlwaysUv = {}", always_uv);
            if !always_uv {
                println!("Error: AlwaysUv is disabled. This configuration is not allowed.");
                println!("Please enable AlwaysUv using the authenticator config command.");
                process::exit(1);
            }
            println!("AlwaysUv is enabled. Configuration is valid.");
        }
        Ok(None) => {
            println!("Error: AlwaysUv option is not supported by this device.");
            process::exit(1);
        }
        Err(e) => {
            println!("Error checking AlwaysUv: {:?}", e);
            process::exit(1);
        }
    }

    println!("----- test-config end -----");
    Ok(())
}
