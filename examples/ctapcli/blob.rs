use crate::common;
use anyhow::{anyhow, Result};
use ctap_hid_fido2::fidokey::{get_info::InfoOption, FidoKeyHid};

pub enum Command {
    Get,
    Set(Vec<u8>),
}

pub fn blob(device: &FidoKeyHid, command: Command, pin: Option<String>) -> Result<()> {
    if !(is_supported(device)?) {
        return Err(anyhow!(
            "This authenticator is not Supported Large Blob Key."
        ));
    }

    match command {
        Command::Get => {
            println!("Large Blob Key.");
            println!("https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-largeBlobKey-extension");
            println!();
            let large_brob_data = device.get_large_blob()?;
            //println!("{}", large_brob_data);
            let converted = String::from_utf8(large_brob_data.large_blob_array.to_vec())?;
            println!("{}", converted);
            println!();
            println!("- done.")
        }
        Command::Set(write_datas) => {
            let pin = if let Some(val) = pin {
                val
            } else {
                common::get_pin()?
            };

            let input = common::get_input_with_message(
                "Would you like to rewrite the Large Blob?. (Yes/No)",
            );
            if input == "Yes" {
                device.write_large_blob(Some(&pin), write_datas)?;
                println!("- done.")
            } else {
                println!("- canceled.")
            }
        }
    }

    Ok(())
}

fn is_supported(device: &FidoKeyHid) -> Result<bool> {
    if device
        .enable_info_option(&InfoOption::LargeBlobs)?
        .is_some()
    {
        Ok(true)
    } else {
        Ok(false)
    }
}
