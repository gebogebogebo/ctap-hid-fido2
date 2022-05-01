use crate::common;
use anyhow::{anyhow, Result};
use ctap_hid_fido2::fidokey::{get_info::InfoOption, FidoKeyHid};

pub enum Command {
    ToggleAlwaysUv,
    SetMinPINLength(u8),
}

pub fn config(device: &FidoKeyHid, command: Command, pin: Option<String>) -> Result<()> {
    if !(is_supported(device)?) {
        return Err(anyhow!(
            "This authenticator is not Supported Authenticator Config."
        ));
    }

    let pin = if let Some(val) = pin {
        val
    } else {
        common::get_pin()
    };

    match command {
        Command::ToggleAlwaysUv => {
            println!("Authenticator Config: Toggle Always Require User Verification.");

            device.toggle_always_uv(Some(&pin))?;
            let result = device.enable_info_option(&InfoOption::AlwaysUv)?;
            println!("- done. -> {:?} is {:?}", InfoOption::AlwaysUv, result);
        }
        Command::SetMinPINLength(new_min_pin_length) => {
            println!("Authenticator Config: Setting a minimum PIN Length.");
            let info = device.get_info()?;
            let input = common::get_input_with_message(
                &format!("[Cannot be restored]\nChange setting from {} to {}. (Yes/No)",info.min_pin_length,new_min_pin_length)
            );
            if input == "Yes" {
                device.set_min_pin_length(new_min_pin_length, Some(&pin))?;
                println!("Complete.")
            } else {
                println!("Canceled.")
            }

        }
    }

    Ok(())
}

fn is_supported(device: &FidoKeyHid) -> Result<bool> {
    if device
        .enable_info_option(&&InfoOption::AuthnrCfg)?
        .is_some()
    {
        Ok(true)
    } else {
        Ok(false)
    }
}
