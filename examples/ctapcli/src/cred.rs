use crate::str_buf::StrBuf;
use anyhow::Result;
use ctap_hid_fido2;

#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::HidParam;

pub fn cred(matches: &clap::ArgMatches) -> Result<()> {
    let pin = matches.value_of("pin");

    println!("Enumerate discoverable credentials.");

    let credentials_count = match ctap_hid_fido2::credential_management_get_creds_metadata(
        &HidParam::get_default_params(),
        pin,
    ) {
        Ok(result) => result,
        Err(e) => return Err(e),
    };

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
    let rps = match ctap_hid_fido2::credential_management_enumerate_rps(&HidParam::get_default_params(), pin)
    {
        Ok(results) => results,
        Err(e) => return Err(e),
    };

    for r in rps {
        println!("## rps\n{}", r);

        let creds = match ctap_hid_fido2::credential_management_enumerate_credentials(
            &HidParam::get_default_params(),
            pin,
            r.rpid_hash
        ) {
            Ok(results) => results,
            Err(e) => return Err(e),
        };

        for c in creds {
            println!("### credentials\n{}", c);
        }

    }

    Ok(())
}
