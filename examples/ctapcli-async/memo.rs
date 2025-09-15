use anyhow::{anyhow, Result};
use arboard::Clipboard;

use ctap_hid_fido2::fidokey::{
    credential_management::credential_management_params::{Credential, Rp},
    get_info::InfoOption,
    FidoKeyHidAsync,
};

use crate::common;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;

pub enum Command {
    List,
    Add,
    Del(String),
    Get(String),
}

pub async fn memo(device: &FidoKeyHidAsync, command: Command) -> Result<()> {
    if !(is_supported(device).await?) {
        return Err(anyhow!(
            "This authenticator is not supported for this functions."
        ));
    }

    // Title
    match command {
        Command::Add => println!("Add a memo."),
        Command::List => println!("List All memo."),
        Command::Del(_) => println!("Delete a memo."),
        Command::Get(_) => println!("Get a memo."),
    }

    let pin = common::get_pin().await?;
    let rpid = "ctapcli";

    // main
    match command {
        Command::Add => {
            let tag = common::get_input_with_message("tag:").await?;
            add_tag(device, &tag, &pin, rpid).await?;
        }
        Command::List => {
            list_tag(device, &pin, rpid).await?;
        }
        Command::Del(tag) => {
            del(device, &tag, &pin, rpid).await?;
        }
        Command::Get(tag) => {
            if tag.is_empty() {
                list_tag(device, &pin, rpid).await?;
                let tag = common::get_input_with_message("tag:").await?;
                get(device, &tag, &pin, rpid).await?;
            } else {
                get(device, &tag, &pin, rpid).await?;
            }
        }
    }

    Ok(())
}

async fn add_tag(device: &FidoKeyHidAsync, tag: &str, pin: &str, rpid: &str) -> Result<()> {
    if search_cred(device, pin, rpid, tag.as_bytes()).await?.is_none() {
        let memo = common::get_input_with_message("memo:").await?;

        let challenge = verifier::create_challenge();
        let rkparam = PublicKeyCredentialUserEntity::new(Some(tag.as_bytes()), Some(memo.as_str()), None);

        let _att = device.make_credential_rk(rpid, &challenge, Some(pin), &rkparam).await?;

        println!("Add Success! :)");
    } else {
        println!("This tag already exists :(");
    }

    Ok(())
}

async fn del(device: &FidoKeyHidAsync, tag: &str, pin: &str, rpid: &str) -> Result<()> {
    if let Some(cred) = search_cred(device, pin, rpid, tag.as_bytes()).await? {
        device.credential_management_delete_credential(
            Some(pin),
            cred.public_key_credential_descriptor,
        ).await?;

        println!("Delete Success!.");
    } else {
        println!("tag not found...");
    }
    Ok(())
}

async fn list_tag(device: &FidoKeyHidAsync, pin: &str, rpid: &str) -> Result<()> {
    let rps = get_rps(device, Some(pin)).await?;
    let mut rps = rps
        .iter()
        .filter(|it| it.public_key_credential_rp_entity.id == rpid);

    if let Some(r) = rps.next() {
        let creds = device.credential_management_enumerate_credentials(Some(pin), &r.rpid_hash).await?;

        for id in creds
            .iter()
            .map(|it| it.public_key_credential_user_entity.id.to_vec())
        {
            let tag = String::from_utf8(id)?;
            println!("- {}", tag);
        }

        println!("({}/10)", creds.len());
        println!();
        Ok(())
    } else {
        Err(anyhow!("No memo is registered."))
    }
}

async fn is_supported(device: &FidoKeyHidAsync) -> Result<bool> {
    if device
        .enable_info_option(&InfoOption::CredentialMgmtPreview).await?
        .is_some()
    {
        return Ok(true);
    }

    if device.enable_info_option(&InfoOption::CredMgmt).await?.is_some() {
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn get_rps(device: &FidoKeyHidAsync, pin: Option<&str>) -> Result<Vec<Rp>> {
    match device.credential_management_enumerate_rps(pin).await {
        Ok(rps) => Ok(rps),
        Err(e) => {
            // 0x2E CTAP2_ERR_NO_CREDENTIALS is not error
            if e.to_string().contains("0x2E") {
                Ok(vec![])
            } else {
                Err(e)
            }
        }
    }

    //ctap_hid_fido2::credential_management_enumerate_rps(&CFG, pin)
}

pub async fn search_cred(
    device: &FidoKeyHidAsync,
    pin: &str,
    rpid: &str,
    user_entity_id: &[u8],
) -> Result<Option<Credential>> {
    let rps = get_rps(device, Some(pin)).await?;

    let mut rps = rps
        .iter()
        .filter(|it| it.public_key_credential_rp_entity.id == rpid);

    if let Some(r) = rps.next() {
        let creds = device.credential_management_enumerate_credentials(Some(pin), &r.rpid_hash).await?;

        let mut creds = creds
            .iter()
            .filter(|it| it.public_key_credential_user_entity.id.eq(user_entity_id));

        if let Some(c) = creds.next() {
            return Ok(Some(c.clone()));
        }
    }
    Ok(None)
}

async fn get(device: &FidoKeyHidAsync, tag: &str, pin: &str, rpid: &str) -> Result<()> {
    if let Some(cred) = search_cred(device, pin, rpid, tag.as_bytes()).await? {
        let data = cred.public_key_credential_user_entity.name;

        let mut clipboard = Clipboard::new().unwrap();
        clipboard.set_text(data).unwrap();

        println!("Copied it to the clipboard :) :) :) !");
    } else {
        println!("tag not found...");
    }
    Ok(())
}
