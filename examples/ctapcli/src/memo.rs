use anyhow::{anyhow, Result, Context};
use ctap_hid_fido2;

#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::{HidParam, InfoOption};

use ctap_hid_fido2::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use ctap_hid_fido2::verifier;

pub fn memo(matches: &clap::ArgMatches) -> Result<()> {
    let pin = matches.value_of("pin");
    let rpid = "ctapcli";

    if let None = ctap_hid_fido2::enable_info_option(
        &HidParam::get_default_params(),
        &InfoOption::CredentialMgmtPreview,
    )? {
        return Err(anyhow!(
            "Sorry , This authenticator is not supported for this functions."
        ));
    }

    if matches.is_present("add") {
        let mut values = matches.values_of("add").context("None")?;
        let tag = values.next().context("None")?;
        let memo = values.next().context("None")?;

        let challenge = verifier::create_challenge();
        let rkparam = PublicKeyCredentialUserEntity::new(Some(tag.as_bytes()), Some(memo), None);

        let _att = ctap_hid_fido2::make_credential_rk(
            &HidParam::get_default_params(),
            rpid,
            &challenge,
            pin,
            &rkparam,
        )?;
    } else if matches.is_present("del") {
        let mut values = matches.values_of("del").unwrap();
        let tag = values.next().unwrap();
        println!("Delete memos => {}.",tag);

        /*
        let mut pkcd = PublicKeyCredentialDescriptor::default();
        pkcd.id = util::to_str_hex(credential_id.unwrap());
        pkcd.ctype = "public_key".to_string();

        match ctap_hid_fido2::credential_management_delete_credential(
            &HidParam::get_default_params(),
            pin,
            Some(pkcd),
        ) {
            Ok(_) => println!("- success"),
            Err(e) => println!("- error: {:?}",e),
        }
        */

    } else {
        println!("List All Memos.");

        let rps = ctap_hid_fido2::credential_management_enumerate_rps(
            &HidParam::get_default_params(),
            pin,
        )?;
        
        let rps = rps.iter().filter(|&x| x.public_key_credential_rp_entity.id == rpid);

        for r in rps {
            //println!("## rps\n{}", r);

            let creds = ctap_hid_fido2::credential_management_enumerate_credentials(
                &HidParam::get_default_params(),
                pin,
                &r.rpid_hash,
            )?;

            for c in creds {
                // tag
                let tag =
                    String::from_utf8(c.public_key_credential_user_entity.id.to_vec()).unwrap();
                println!("- tag = {}", tag);

                // data
                let data = c.public_key_credential_user_entity.name;
                println!("- data = {}", data);

                println!("")

                //println!("### credentials\n{}", c);
            }
        }
    }

    Ok(())
}
