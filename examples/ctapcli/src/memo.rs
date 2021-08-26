use anyhow::{anyhow, Result};

use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;

use crate::common;

#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::{HidParam, InfoOption};

use ctap_hid_fido2::credential_management_params::Credential;
use ctap_hid_fido2::credential_management_params::Rp;
use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;

pub fn memo(matches: &clap::ArgMatches) -> Result<()> {

    // check
    if is_supported()? == false {
        return Err(anyhow!(
            "Sorry , This authenticator is not supported for this functions."
        ));
    }

    // Title
    if matches.is_present("add") {
        println!("Add a memo.");
    } else if matches.is_present("del") {
        println!("Delete a memo.");
    } else if matches.is_present("list") {
        println!("List All memos.");
    } else if matches.is_present("get") {
        println!("Get a memo.");
    } else {
        println!("Get a memo.");
    }

    let pin = common::get_pin();
    let rpid = "ctapcli";

    // main
    if matches.is_present("add") {
        let tag = common::get_input_with_message("tag:");
        add(&tag, &pin, rpid)?;

    } else if matches.is_present("del") {
        let mut values = matches.values_of("del").unwrap();
        let tag = values.next().unwrap();
        del(tag,&pin,rpid)?;

    } else if matches.is_present("list") {
        list(&pin,rpid)?;
    } else if matches.is_present("get") {
        let mut values = matches.values_of("get").unwrap();
        let tag = values.next().unwrap();
        get(tag, &pin, rpid)?;
    } else {
        list(&pin,rpid)?;
        let tag = common::get_input_with_message("tag:");
        get(&tag, &pin, rpid)?;
    }

    Ok(())
}

fn add(tag: &str, pin: &str, rpid: &str) -> Result<()> {
    if let None = search_cred(&pin, rpid, tag.as_bytes())? {
        let memo = common::get_input_with_message("memo:");

        let challenge = verifier::create_challenge();
        let rkparam =
            PublicKeyCredentialUserEntity::new(Some(tag.as_bytes()), Some(&memo), None);

        let _att = ctap_hid_fido2::make_credential_rk(
            &HidParam::get_default_params(),
            rpid,
            &challenge,
            Some(&pin),
            &rkparam,
        )?;

        println!("Add Success! :)");
    } else {
        println!("This tag already exists :(");
    }

    Ok(())
}

fn del(tag: &str, pin: &str, rpid: &str) -> Result<()> {
    if let Some(cred) = search_cred(&pin, rpid, tag.as_bytes())? {
        ctap_hid_fido2::credential_management_delete_credential(
            &HidParam::get_default_params(),
            Some(&pin),
            Some(cred.public_key_credential_descriptor),
        )?;

        println!("Delete Success!.");
    } else {
        println!("tag not found...");
    }
    Ok(())
}

fn list(pin: &str, rpid: &str) -> Result<()> {
    let rps = get_rps(Some(pin))?;
    let mut rps = rps
        .iter()
        .filter(|it| it.public_key_credential_rp_entity.id == rpid);

    if let Some(r) = rps.next() {
        let creds = get_creds(Some(&pin), r)?;

        for id in creds
            .iter()
            .map(|it| it.public_key_credential_user_entity.id.to_vec())
        {
            let tag = String::from_utf8(id)?;
            println!("- {}", tag);
        }

        println!("({}/10)", creds.len());
    }
    println!();

    Ok(())
}

fn is_supported() -> Result<bool> {
    if let None = ctap_hid_fido2::enable_info_option(
        &HidParam::get_default_params(),
        &InfoOption::CredentialMgmtPreview,
    )? {
        if let None = ctap_hid_fido2::enable_info_option(
            &HidParam::get_default_params(),
            &InfoOption::CredMgmt,
        )? {
            return Ok(false);
        }
    }

    Ok(true)
}

fn get_rps(pin: Option<&str>) -> Result<Vec<Rp>> {
    ctap_hid_fido2::credential_management_enumerate_rps(&HidParam::get_default_params(), pin)
}

fn get_creds(pin: Option<&str>, rp: &Rp) -> Result<Vec<Credential>> {
    ctap_hid_fido2::credential_management_enumerate_credentials(
        &HidParam::get_default_params(),
        pin,
        &rp.rpid_hash,
    )
}

fn search_cred(pin: &str, rpid: &str, user_entity_id: &[u8]) -> Result<Option<Credential>> {
    let rps = get_rps(Some(pin))?;

    let mut rps = rps
        .iter()
        .filter(|it| it.public_key_credential_rp_entity.id == rpid);

    if let Some(r) = rps.next() {
        let creds = get_creds(Some(pin), r)?;

        let mut creds = creds
            .iter()
            .filter(|it| it.public_key_credential_user_entity.id.eq(user_entity_id));

        if let Some(c) = creds.next() {
            return Ok(Some(c.clone()));
        }
    }
    Ok(None)
}

fn get(tag: &str, pin: &str, rpid: &str) -> Result<()> {
    if let Some(cred) = search_cred(pin, rpid, tag.as_bytes())? {
        let data = cred.public_key_credential_user_entity.name;

        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        ctx.set_contents(data.to_owned()).unwrap();

        println!("Copied it to the clipboard :) :) :) !");
    } else {
        println!("tag not found...");
    }
    Ok(())
}

