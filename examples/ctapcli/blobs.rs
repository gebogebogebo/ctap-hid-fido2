use crate::common;
use anyhow::{anyhow, Result};
use ctap_hid_fido2::fidokey::{get_info::InfoOption, FidoKeyHid};

pub enum Command {
    Get((u32, u32)),
    Set((u32, Vec<u8>)),
}

pub fn blobs(device: &FidoKeyHid, command: Command, pin: Option<String>) -> Result<()> {
    if !(is_supported(device)?) {
        return Err(anyhow!(
            "This authenticator is not Supported Large Blob Key."
        ));
    }

    let pin = if let Some(val) = pin {
        val
    } else {
        common::get_pin()
    };

    match command {
        Command::Get((offset, read_bytes)) => {
            println!("Large Blob Key.");
            println!("https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-largeBlobKey-extension");
            println!();
            // let always_uv = device.enable_info_option(&InfoOption::AlwaysUv)?.unwrap();
            // let input = common::get_input_with_message(
            //     &format!("Change Require User Verification from [{}] to [{}]. (Yes/No)",always_uv,!always_uv)
            // );
            // if input == "Yes" {
            let large_brob_data = device.large_blobs(Some(&pin), offset, Some(read_bytes), None)?;
            println!("{}",large_brob_data);
            println!("- done.")
            // } else {
            //     println!("- canceled.")
            // }
        }
        Command::Set((offset, write_datas)) => {
            device.large_blobs(Some(&pin), offset, None, Some(write_datas))?;
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
