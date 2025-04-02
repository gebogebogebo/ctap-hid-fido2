use anyhow::{anyhow, Result};
use ctap_hid_fido2::{fidokey::get_info::InfoOption, Cfg, FidoKeyHidFactory};

fn check_info_option(
    dev: &ctap_hid_fido2::FidoKeyHid,
    option: &InfoOption,
    expected_value: bool,
) -> Result<()> {
    let option_name = format!("{:?}", option);
    println!("Checking {} setting...", option_name);
    
    match dev.enable_info_option(option) {
        Ok(Some(enabled)) => {
            println!("{} = {}", option_name, enabled);
            if enabled != expected_value {
                let status = if expected_value { "disabled" } else { "enabled" };
                return Err(anyhow!("{} is {}. This configuration is not allowed", option_name, status));
            }
            let status = if expected_value { "enabled" } else { "disabled" };
            println!("{} is {}. Configuration is valid.", option_name, status);
            Ok(())
        }
        Ok(None) => {
            Err(anyhow!("{} option is not supported by this device", option_name))
        }
        Err(e) => {
            Err(anyhow!("Error checking {}: {:?}", option_name, e))
        }
    }
}

fn main() -> Result<()> {
    println!("----- test-config start -----");
    let pin = "1234";

    let devs = ctap_hid_fido2::get_fidokey_devices();
    if devs.len() != 1 {
        return Err(anyhow!("Exactly one FIDO device must be connected"));
    }

    let dev = FidoKeyHidFactory::create(&Cfg::init())?;

    // AlwaysUv
    check_info_option(&dev, &InfoOption::AlwaysUv, true)?;

    // AlwaysUv: true -> false
    dev.toggle_always_uv(Some(&pin))?;
    check_info_option(&dev, &InfoOption::AlwaysUv, false)?;

    // AlwaysUv: false -> true
    dev.toggle_always_uv(Some(&pin))?;
    check_info_option(&dev, &InfoOption::AlwaysUv, true)?;

    //
    println!("----- test-config end -----");
    Ok(())
}
