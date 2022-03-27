use anyhow::{anyhow, Result};
use ctap_hid_fido2::InfoOption;
use crate::str_buf::StrBuf;
use crate::CFG;
use crate::common;

pub fn cred(matches: &clap::ArgMatches) -> Result<()> {
    // check
    if ctap_hid_fido2::enable_info_option(&CFG, &InfoOption::CredMgmt)?.is_none()
        && ctap_hid_fido2::enable_info_option(&CFG, &InfoOption::CredentialMgmtPreview)?
            .is_none()
    {
        return Err(anyhow!(
            "This authenticator is not Supported Credential management."
        ));
    };

    let pin = common::get_pin();

    if matches.is_present("metadata") {
        println!("# credential_management_get_creds_metadata()");
        metadata(&pin);
        return Ok(());
    }

    println!("Enumerate discoverable credentials.");

    let credentials_count =
        ctap_hid_fido2::credential_management_get_creds_metadata(&CFG, Some(&pin))?;

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
    let rps = ctap_hid_fido2::credential_management_enumerate_rps(&CFG, Some(&pin))?;

    for r in rps {
        println!("## rps\n{}", r);

        let creds = ctap_hid_fido2::credential_management_enumerate_credentials(
            &CFG,
            Some(&pin),
            &r.rpid_hash,
        )?;

        for c in creds {
            println!("### credentials\n{}", c);
        }
    }

    Ok(())
}

fn metadata(pin: &str) {
    match ctap_hid_fido2::credential_management_get_creds_metadata(
        &CFG,
        Some(pin),
    ) {
        Ok(result) => println!("{}", result),
        Err(e) => println!("- error: {:?}", e),
    }
}

