use anyhow::{anyhow, Result};
use ctap_hid_fido2::{fidokey::get_info::InfoOption, Cfg, FidoKeyHidFactory};

fn main() -> Result<()> {
    println!("----- test-config start -----");

    let devs = ctap_hid_fido2::get_fidokey_devices();
    if devs.len() != 1 {
        return Err(anyhow!("Exactly one FIDO device must be connected"));
    }

    let dev = FidoKeyHidFactory::create(&Cfg::init())?;

    println!("Checking AlwaysUv setting...");
    match dev.enable_info_option(&InfoOption::AlwaysUv) {
        Ok(Some(always_uv)) => {
            println!("AlwaysUv = {}", always_uv);
            if !always_uv {
                return Err(anyhow!("AlwaysUv is disabled. This configuration is not allowed"));
            }
            println!("AlwaysUv is enabled. Configuration is valid.");
        }
        Ok(None) => {
            return Err(anyhow!("AlwaysUv option is not supported by this device"));
        }
        Err(e) => {
            return Err(anyhow!("Error checking AlwaysUv: {:?}", e));
        }
    }

    println!("----- test-config end -----");
    Ok(())
}
