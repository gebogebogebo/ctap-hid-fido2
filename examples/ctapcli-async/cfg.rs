use crate::common;
use anyhow::{anyhow, Result};
use ctap_hid_fido2::fidokey::{get_info::InfoOption, FidoKeyHidAsync};

pub enum Command {
    ToggleAlwaysUv,
    SetMinPINLength(u8),
    SetMinPinLengthRPIDs(Vec<String>),
    ForceChangePin,
}

pub async fn config(device: &FidoKeyHidAsync, command: Command, pin: Option<String>) -> Result<()> {
    if !(is_supported(device).await?) {
        return Err(anyhow!(
            "This authenticator is not Supported Authenticator Config."
        ));
    }

    let pin = if let Some(val) = pin {
        val
    } else {
        common::get_pin().await?
    };

    match command {
        Command::ToggleAlwaysUv => {
            println!("Authenticator Config: Toggle Always Require User Verification.");
            println!("https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-feature-descriptions-alwaysUv");
            println!();
            let always_uv = device.enable_info_option(&InfoOption::AlwaysUv).await?.unwrap();
            let input = common::get_input_with_message(&format!(
                "Change Require User Verification from [{}] to [{}]. (Yes/No)",
                always_uv, !always_uv
            )).await?;
            if input == "Yes" {
                device.toggle_always_uv(Some(&pin)).await?;
                println!("- done.")
            } else {
                println!("- canceled.")
            }
        }
        Command::SetMinPINLength(new_min_pin_length) => {
            println!("Authenticator Config: Setting a minimum PIN Length.");
            println!("NOTE: The authenticator must be reset to return the current minimum PIN length to the pre-configured minimum PIN length.");
            println!("https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-feature-descriptions-minPinLength");
            println!();
            let info = device.get_info().await?;
            let input = common::get_input_with_message(
                &format!("[WARNING] Cannot be restored\nChange minimum PIN Length from [{}] to [{}] ?. (Yes/No)",info.min_pin_length,new_min_pin_length)
            ).await?;
            if input == "Yes" {
                device.set_min_pin_length(new_min_pin_length, Some(&pin)).await?;
                println!("- done.")
            } else {
                println!("- canceled.")
            }
        }
        Command::SetMinPinLengthRPIDs(rpids) => {
            println!("Authenticator Config: RP IDs which are allowed to get this information via the minPinLength extension.");
            println!("https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-feature-descriptions-minPinLength");
            println!();
            let input = common::get_input_with_message(&format!(
                "[WARNING] Cannot be restored\nSet RP-ID ? {:?}. (Yes/No)",
                rpids
            )).await?;

            if input == "Yes" {
                device.set_min_pin_length_rpids(rpids, Some(&pin)).await?;
                println!("- done.")
            } else {
                println!("- canceled.")
            }
        }
        Command::ForceChangePin => {
            println!("Force Change PIN: PIN change is required after this command.\nThe authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION until changePIN is successful.");
            println!("https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-feature-descriptions-minPinLength");
            println!();
            let input = common::get_input_with_message("[WARNING] Cannot be restored\nForce Change PIN ?. (Yes/No)").await?;

            if input == "Yes" {
                device.force_change_pin(Some(&pin)).await?;
                println!("- done.")
            } else {
                println!("- canceled.")
            }
        }
    }

    Ok(())
}

async fn is_supported(device: &FidoKeyHidAsync) -> Result<bool> {
    if device.enable_info_option(&InfoOption::AuthnrCfg).await?.is_some() {
        Ok(true)
    } else {
        Ok(false)
    }
}
