use crate::str_buf::StrBuf;
use anyhow::{anyhow, Result};

#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::{HidParam, InfoOption};

pub fn cred(matches: &clap::ArgMatches) -> Result<()> {
    let pin = matches.value_of("pin");

    // check
    if let None =
        ctap_hid_fido2::enable_info_option(&HidParam::get_default_params(), &InfoOption::CredMgmt)?
    {
        if let None = ctap_hid_fido2::enable_info_option(
            &HidParam::get_default_params(),
            &InfoOption::CredentialMgmtPreview,
        )? {
            return Err(anyhow!(
                "This authenticator is not Supported Credential management."
            ));
        }
    };

    println!("Enumerate discoverable credentials.");

    let credentials_count = ctap_hid_fido2::credential_management_get_creds_metadata(
        &HidParam::get_default_params(),
        pin,
    )?;

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

    if credentials_count.existing_resident_credentials_count <= 0 {
        println!("\nNo discoverable credentials.");
        return Ok(());
    }

    // Vec<credential_management_params::Rp>
    let rps =
        ctap_hid_fido2::credential_management_enumerate_rps(&HidParam::get_default_params(), pin)?;

    for r in rps {
        println!("## rps\n{}", r);

        let creds = ctap_hid_fido2::credential_management_enumerate_credentials(
            &HidParam::get_default_params(),
            pin,
            &r.rpid_hash,
        )?;

        for c in creds {
            println!("### credentials\n{}", c);
        }
    }

    Ok(())
}
