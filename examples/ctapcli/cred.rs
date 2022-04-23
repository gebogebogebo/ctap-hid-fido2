use anyhow::{anyhow, Result};
use ctap_hid_fido2::{
    fidokey::{
        get_info::InfoOption,
        FidoKeyHid,
    },
    public_key_credential_descriptor::PublicKeyCredentialDescriptor,
    public_key_credential_user_entity::PublicKeyCredentialUserEntity,
};
use crate::{
    common,
    util,
    str_buf::StrBuf,
};

pub fn cred(device: &FidoKeyHid, matches: &clap::ArgMatches) -> Result<()> {
    if !(is_supported(device)?) {
        return Err(anyhow!(
            "This authenticator is not Supported Credential management."
        ));
    }

    let pin = common::get_pin();

    if matches.is_present("metadata") {
        println!("# credential_management_get_creds_metadata()");
        metadata(device, &pin);
        return Ok(());
    } else if matches.is_present("delete") {
        let credential_id = matches.value_of("delete");
        delete(device, &pin, credential_id.unwrap())?;
        return Ok(());
    } else if matches.is_present("update") {
        let credential_id = matches.value_of("update");
        update(device, &pin, credential_id.unwrap())?;
        return Ok(());
    }

    println!("Enumerate discoverable credentials.");

    let credentials_count = device.credential_management_get_creds_metadata(Some(&pin))?;

    let mut strbuf = StrBuf::new(0);
    strbuf.addln(&format!(
        "Existing discoverable credentials {}/{}",
        credentials_count.existing_resident_credentials_count,
        credentials_count.max_possible_remaining_resident_credentials_count
    ));
    strbuf
        .addln("")
        .addln("Discoverable credentials")
        .addln("https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-discoverable");

    println!("{}", strbuf.build().to_string());

    if credentials_count.existing_resident_credentials_count == 0 {
        println!("\nNo discoverable credentials.");
        return Ok(());
    }

    // Vec<credential_management_params::Rp>
    let rps = device.credential_management_enumerate_rps(Some(&pin))?;

    for r in rps {
        println!("## rps\n{}", r);

        let creds = device.credential_management_enumerate_credentials(Some(&pin), &r.rpid_hash)?;

        for c in creds {
            println!("### credentials\n{}", c);
        }
    }

    Ok(())
}

fn metadata(device: &FidoKeyHid, pin: &str) {
    match device.credential_management_get_creds_metadata(Some(pin)) {
        Ok(result) => println!("{}", result),
        Err(e) => println!("- error: {:?}", e),
    }
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

fn delete(device: &FidoKeyHid, pin: &str, credential_id: &str) -> Result<()> {
    println!("Delete a Credential.");
    println!("value for credential_id: {:?}", credential_id);
    println!();

    let mut pkcd = PublicKeyCredentialDescriptor::default();
    pkcd.id = util::to_str_hex(credential_id);
    pkcd.ctype = "public_key".to_string();

    device.credential_management_delete_credential(Some(pin), Some(pkcd))?;
    println!("- Success\n");
    Ok(())
}

fn update(device: &FidoKeyHid, pin: &str, credential_id: &str) -> Result<()> {
    println!("Update a Credential User Info.");
    println!("- value for credential_id: {:?}", credential_id);
    println!();

    let mut pkcd = PublicKeyCredentialDescriptor::default();
    pkcd.id = util::to_str_hex(credential_id);
    pkcd.ctype = "public_key".to_string();

    let mut pkcue = PublicKeyCredentialUserEntity::default();
    pkcue.id = util::to_str_hex("7573657232");
    pkcue.name = "test-name".to_string();
    pkcue.display_name = "test-display".to_string();

    device.credential_management_update_user_information(Some(pin), Some(pkcd), Some(pkcue))?;
    println!("- Success\n");
    Ok(())
}

