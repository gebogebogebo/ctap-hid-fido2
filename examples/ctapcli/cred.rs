use crate::{common, memo, util};
use anyhow::{anyhow, Result};
use ctap_hid_fido2::{
    fidokey::{get_info::InfoOption, FidoKeyHid},
    public_key_credential_user_entity::PublicKeyCredentialUserEntity,
};

pub enum Command {
    Metadata,
    List,
    Del((String, String)),
    Update((String, String)),
}

pub fn cred(device: &FidoKeyHid, command: Command) -> Result<()> {
    if !(is_supported(device)?) {
        return Err(anyhow!(
            "This authenticator is not Supported Credential management."
        ));
    }

    let pin = common::get_pin();

    match command {
        Command::List => {
            println!("Enumerate discoverable credentials.");
            enumerate(device, &pin)?;
        }
        Command::Metadata => {
            println!("Getting Credentials Metadata.");
            metadata(device, &pin)?;
        }
        Command::Del((rpid, user_id)) => {
            println!("Delete a Credential.");

            if rpid.is_empty() || user_id.is_empty() {
                return Err(anyhow!("Need rpid and userid."));
            }

            println!("- credential: (rpid: {}, user_id: {})", rpid, user_id);
            println!();

            delete(device, &pin, &rpid, &util::to_str_hex(&user_id))?;
        }
        Command::Update((rpid, user_id)) => {
            println!("Update a Credential.");

            if rpid.is_empty() || user_id.is_empty() {
                return Err(anyhow!("Need rpid and userid."));
            }

            println!("- credential: (rpid: {}, user_id: {})", rpid, user_id);
            println!();

            update(device, &pin, &rpid, &util::to_str_hex(&user_id))?;
        }
    }
    Ok(())
}

fn is_supported(device: &FidoKeyHid) -> Result<bool> {
    if device.enable_info_option(&InfoOption::CredMgmt)?.is_some() {
        return Ok(true);
    }

    if device
        .enable_info_option(&&InfoOption::CredentialMgmtPreview)?
        .is_some()
    {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn metadata(device: &FidoKeyHid, pin: &str) -> Result<()> {
    let metadata = device.credential_management_get_creds_metadata(Some(pin))?;
    println!("{}", metadata);
    Ok(())
}

fn enumerate(device: &FidoKeyHid, pin: &str) -> Result<()> {
    let credentials_count = device.credential_management_get_creds_metadata(Some(&pin))?;
    println!(
        "- existing discoverable credentials: {}/{}",
        credentials_count.existing_resident_credentials_count,
        credentials_count.max_possible_remaining_resident_credentials_count
    );

    if credentials_count.existing_resident_credentials_count == 0 {
        println!("\nNo discoverable credentials.");
        return Ok(());
    }

    let rps = device.credential_management_enumerate_rps(Some(&pin))?;

    for rp in rps {
        println!(
            "- rp: (id: {}, name: {})",
            rp.public_key_credential_rp_entity.id, rp.public_key_credential_rp_entity.name
        );
        //println!("## rps\n{}", rp);

        let creds =
            device.credential_management_enumerate_credentials(Some(&pin), &rp.rpid_hash)?;
        for cred in creds {
            println!(
                "  - credential: (id: {}, name: {}, display_name: {})",
                util::to_hex_str(&cred.public_key_credential_user_entity.id),
                cred.public_key_credential_user_entity.name,
                cred.public_key_credential_user_entity.display_name
            );
            //println!("### credentials\n{}", cred);
        }
    }

    Ok(())
}

fn delete(device: &FidoKeyHid, pin: &str, rpid: &str, user_id: &[u8]) -> Result<()> {
    if let Some(cred) = memo::search_cred(device, pin, rpid, user_id)? {
        device.credential_management_delete_credential(
            Some(pin),
            Some(cred.public_key_credential_descriptor),
        )?;
        println!("Delete Success!");
    } else {
        println!("Credential not found...");
    }
    Ok(())
}

fn update(device: &FidoKeyHid, pin: &str, rpid: &str, user_id: &[u8]) -> Result<()> {
    if let Some(cred) = memo::search_cred(device, pin, rpid, user_id)? {
        let mut pkcue = PublicKeyCredentialUserEntity::default();
        pkcue.id = util::to_str_hex("7573657232");
        pkcue.name = "test-name".to_string();
        pkcue.display_name = "test-display".to_string();

        device.credential_management_update_user_information(
            Some(pin),
            Some(cred.public_key_credential_descriptor),
            Some(pkcue),
        )?;

        println!("Update Success!");
    } else {
        println!("Credential not found...");
    }
    Ok(())
}
