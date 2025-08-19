use crate::{common, memo, util};
use anyhow::{anyhow, Result};
use ctap_hid_fido2::{
    fidokey::{get_info::InfoOption, FidoKeyHidAsync},
    public_key_credential_user_entity::PublicKeyCredentialUserEntity,
};

pub enum Command {
    Metadata,
    List,
    Del((String, String)),
    Update((String, String)),
}

pub async fn cred(device: &FidoKeyHidAsync, command: Command, pin: Option<String>) -> Result<()> {
    if !(is_supported(device).await?) {
        return Err(anyhow!(
            "This authenticator is not Supported Credential management."
        ));
    }

    let pin = if let Some(val) = pin {
        val
    } else {
        common::get_pin().await?
    };

    match command {
        Command::List => {
            println!("Enumerate discoverable credentials.");
            enumerate(device, &pin).await?;
        }
        Command::Metadata => {
            println!("Getting Credentials Metadata.");
            metadata(device, &pin).await?;
        }
        Command::Del((rpid, user_id)) => {
            println!("Delete a Credential.");

            if rpid.is_empty() || user_id.is_empty() {
                return Err(anyhow!("Need rpid and userid."));
            }

            println!("- credential: (rpid: {}, user_id: {})", rpid, user_id);
            println!();

            delete(device, &pin, &rpid, &util::to_str_hex(&user_id)).await?;
        }
        Command::Update((rpid, user_id)) => {
            println!("Update a Credential.");

            if rpid.is_empty() || user_id.is_empty() {
                return Err(anyhow!("Need rpid and userid."));
            }

            println!("- credential: (rpid: {}, user_id: {})", rpid, user_id);
            println!();

            update(device, &pin, &rpid, &util::to_str_hex(&user_id)).await?;
        }
    }
    Ok(())
}

async fn is_supported(device: &FidoKeyHidAsync) -> Result<bool> {
    if device.enable_info_option(&InfoOption::CredMgmt).await?.is_some() {
        return Ok(true);
    }

    if device
        .enable_info_option(&InfoOption::CredentialMgmtPreview).await?
        .is_some()
    {
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn metadata(device: &FidoKeyHidAsync, pin: &str) -> Result<()> {
    let metadata = device.credential_management_get_creds_metadata(Some(pin)).await?;
    println!("{}", metadata);
    Ok(())
}

async fn enumerate(device: &FidoKeyHidAsync, pin: &str) -> Result<()> {
    let credentials_count = device.credential_management_get_creds_metadata(Some(pin)).await?;
    println!(
        "- existing discoverable credentials: {}/{}",
        credentials_count.existing_resident_credentials_count,
        credentials_count.max_possible_remaining_resident_credentials_count
    );

    if credentials_count.existing_resident_credentials_count == 0 {
        println!("\nNo discoverable credentials.");
        return Ok(());
    }

    let rps = device.credential_management_enumerate_rps(Some(pin)).await?;

    for rp in rps {
        println!(
            "- rp: (id: {}, name: {})",
            rp.public_key_credential_rp_entity.id, rp.public_key_credential_rp_entity.name
        );
        //println!("## rps\n{}", rp);

        let creds = device.credential_management_enumerate_credentials(Some(pin), &rp.rpid_hash).await?;
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

async fn delete(device: &FidoKeyHidAsync, pin: &str, rpid: &str, user_id: &[u8]) -> Result<()> {
    if let Some(cred) = memo::search_cred(device, pin, rpid, user_id).await? {
        device.credential_management_delete_credential(
            Some(pin),
            cred.public_key_credential_descriptor,
        ).await?;
        println!("Delete Success!");
    } else {
        println!("Credential not found...");
    }
    Ok(())
}

async fn update(device: &FidoKeyHidAsync, pin: &str, rpid: &str, user_id: &[u8]) -> Result<()> {
    if let Some(cred) = memo::search_cred(device, pin, rpid, user_id).await? {
        let pkcue = PublicKeyCredentialUserEntity {
            id: user_id.to_vec(),
            name: "test-name".to_string(),
            display_name: "test-display".to_string(),
        };

        device.credential_management_update_user_information(
            Some(pin),
            cred.public_key_credential_descriptor,
            pkcue,
        ).await?;

        println!("Update Success!");
    } else {
        println!("Credential not found...");
    }
    Ok(())
}
