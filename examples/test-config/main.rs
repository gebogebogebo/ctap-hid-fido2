use anyhow::{anyhow, Result};
use ctap_hid_fido2::{fidokey::get_info::InfoOption, Cfg, FidoKeyHidFactory};
use std::convert::TryFrom;

fn main() -> Result<()> {
    println!("----- test-config start -----");
    let pin = "1234";

    let devs = ctap_hid_fido2::get_fidokey_devices();
    if devs.len() != 1 {
        return Err(anyhow!("Exactly one FIDO device must be connected"));
    }

    let dev = FidoKeyHidFactory::create(&Cfg::init())?;

    //
    // AlwaysUv
    //
    check_info_option(&dev, &InfoOption::AlwaysUv, true)?;
    dev.toggle_always_uv(Some(pin))?;
    check_info_option(&dev, &InfoOption::AlwaysUv, false)?;
    dev.toggle_always_uv(Some(pin))?;
    check_info_option(&dev, &InfoOption::AlwaysUv, true)?;

    //
    // set_min_pin_length
    //
    check_min_pin_length(&dev, 4)?;
    dev.set_min_pin_length(4, Some(pin))?;
    check_min_pin_length(&dev, 4)?;

    //
    // Force Change PIN
    //
    check_force_pin_change(&dev, false)?;
    dev.force_change_pin(Some(pin))?;
    check_force_pin_change(&dev, true)?;
    dev.change_pin(pin, "12345")?;
    dev.change_pin("12345", pin)?;
    check_force_pin_change(&dev, false)?;

    println!("----- test-config end -----");
    Ok(())
}

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

fn check_min_pin_length(dev: &ctap_hid_fido2::FidoKeyHid, expected_length: u8) -> Result<()> {
    println!("Checking minimum PIN length...");
    
    match dev.get_info() {
        Ok(info_response) => {
            let min_pin_length = u8::try_from(info_response.min_pin_length).unwrap_or(0);
            println!("Minimum PIN length = {}", min_pin_length);
            
            if min_pin_length != expected_length {
                return Err(anyhow!(
                    "Minimum PIN length is {}. Expected: {}. This configuration is not allowed", 
                    min_pin_length, 
                    expected_length
                ));
            }
            
            println!("Minimum PIN length is {}. Configuration is valid.", min_pin_length);
            Ok(())
        }
        Err(e) => {
            Err(anyhow!("Error checking minimum PIN length: {:?}", e))
        }
    }
}

fn check_force_pin_change(dev: &ctap_hid_fido2::FidoKeyHid, expected_value: bool) -> Result<()> {
    println!("Checking force PIN change setting...");
    
    match dev.get_info() {
        Ok(info_response) => {
            let force_pin_change = info_response.force_pin_change;
            println!("Force PIN change = {}", force_pin_change);
            
            if force_pin_change != expected_value {
                return Err(anyhow!(
                    "Force PIN change is {}. Expected: {}. This configuration is not allowed", 
                    if force_pin_change { "enabled" } else { "disabled" }, 
                    if expected_value { "enabled" } else { "disabled" }
                ));
            }
            
            println!("Force PIN change is {}. Configuration is valid.", 
                    if force_pin_change { "enabled" } else { "disabled" });
            Ok(())
        }
        Err(e) => {
            Err(anyhow!("Error checking force PIN change: {:?}", e))
        }
    }
}
