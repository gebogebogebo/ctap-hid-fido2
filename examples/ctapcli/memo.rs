use anyhow::{anyhow, Result};

#[cfg(not(target_os = "linux"))]
use clipboard::{ClipboardContext, ClipboardProvider};

use ctap_hid_fido2::fidokey::{
    credential_management::credential_management_params::{Credential, Rp},
    get_info::InfoOption,
    FidoKeyHid,
};

use crate::common;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;

pub fn memo(device: &FidoKeyHid, add: bool, list: bool, get_tag: &str, del_tag: &str) -> Result<()> {
    if !(is_supported(device)?) {
        return Err(anyhow!(
            "This authenticator is not supported for this functions."
        ));
    }

    // Title
    if add {
        println!("Add a memo.");
    } else if list {
        println!("List All memos.");
    } else if !del_tag.is_empty() {
        println!("Delete a memo.");
    } else if !get_tag.is_empty(){
        println!("Get a memo.");
    }

    let pin = common::get_pin();
    let rpid = "ctapcli";

    // main
    if add {
        let tag = common::get_input_with_message("tag:");
        add_tag(device, &tag, &pin, rpid)?;
    } else if !del_tag.is_empty() {
        del(device, del_tag, &pin, rpid)?;
    } else if list {
        list_tag(device, &pin, rpid)?;
    } else if !get_tag.is_empty() {
        get(device, get_tag, &pin, rpid)?;
    } else {
        list_tag(device, &pin, rpid)?;
        let tag = common::get_input_with_message("tag:");
        get(device, &tag, &pin, rpid)?;
    }

    Ok(())
}

fn add_tag(device: &FidoKeyHid, tag: &str, pin: &str, rpid: &str) -> Result<()> {
    if search_cred(device, pin, rpid, tag.as_bytes())?.is_none() {
        let memo = common::get_input_with_message("memo:");

        let challenge = verifier::create_challenge();
        let rkparam = PublicKeyCredentialUserEntity::new(Some(tag.as_bytes()), Some(&memo), None);

        let _att = device.make_credential_rk(rpid, &challenge, Some(pin), &rkparam)?;

        println!("Add Success! :)");
    } else {
        println!("This tag already exists :(");
    }

    Ok(())
}

fn del(device: &FidoKeyHid, tag: &str, pin: &str, rpid: &str) -> Result<()> {
    if let Some(cred) = search_cred(device, pin, rpid, tag.as_bytes())? {
        device.credential_management_delete_credential(
            Some(pin),
            Some(cred.public_key_credential_descriptor),
        )?;

        println!("Delete Success!.");
    } else {
        println!("tag not found...");
    }
    Ok(())
}

fn list_tag(device: &FidoKeyHid, pin: &str, rpid: &str) -> Result<()> {
    let rps = get_rps(device, Some(pin))?;
    let mut rps = rps
        .iter()
        .filter(|it| it.public_key_credential_rp_entity.id == rpid);

    if let Some(r) = rps.next() {
        let creds = device.credential_management_enumerate_credentials(Some(pin), &r.rpid_hash)?;

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

fn is_supported(device: &FidoKeyHid) -> Result<bool> {
    if device
        .enable_info_option(&InfoOption::CredentialMgmtPreview)?
        .is_some()
    {
        return Ok(true);
    }

    if device.enable_info_option(&InfoOption::CredMgmt)?.is_some() {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn get_rps(device: &FidoKeyHid, pin: Option<&str>) -> Result<Vec<Rp>> {
    match device.credential_management_enumerate_rps(pin) {
        Ok(rps) => Ok(rps),
        Err(e) => {
            // 0x2E CTAP2_ERR_NO_CREDENTIALS is not error
            if e.to_string().find("0x2E").is_some() {
                Ok(vec![])
            } else {
                Err(e)
            }
        }
    }

    //ctap_hid_fido2::credential_management_enumerate_rps(&CFG, pin)
}

pub fn search_cred(
    device: &FidoKeyHid,
    pin: &str,
    rpid: &str,
    user_entity_id: &[u8],
) -> Result<Option<Credential>> {
    let rps = get_rps(device, Some(pin))?;

    let mut rps = rps
        .iter()
        .filter(|it| it.public_key_credential_rp_entity.id == rpid);

    if let Some(r) = rps.next() {
        let creds = device.credential_management_enumerate_credentials(Some(pin), &r.rpid_hash)?;

        let mut creds = creds
            .iter()
            .filter(|it| it.public_key_credential_user_entity.id.eq(user_entity_id));

        if let Some(c) = creds.next() {
            return Ok(Some(c.clone()));
        }
    }
    Ok(None)
}

#[cfg(not(target_os = "linux"))]
fn get(device: &FidoKeyHid, tag: &str, pin: &str, rpid: &str) -> Result<()> {
    if let Some(cred) = search_cred(device, pin, rpid, tag.as_bytes())? {
        let data = cred.public_key_credential_user_entity.name;

        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        ctx.set_contents(data).unwrap();

        println!("Copied it to the clipboard :) :) :) !");
    } else {
        println!("tag not found...");
    }
    Ok(())
}

// for pi
#[cfg(target_os = "linux")]
fn get(device: &FidoKeyHid, tag: &str, pin: &str, rpid: &str) -> Result<()> {
    if let Some(cred) = search_cred(device, pin, rpid, tag.as_bytes())? {
        let data = cred.public_key_credential_user_entity.name;
        println!("tag found :) :) :) !");
        println!("{:?}", data);
    } else {
        println!("tag not found...");
    }
    Ok(())
}
