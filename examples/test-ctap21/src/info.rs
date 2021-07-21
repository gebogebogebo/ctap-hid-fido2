use ctap_hid_fido2;
use anyhow::{anyhow,Result};

#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::{HidParam, InfoOption, InfoParam};

pub fn info(matches: &clap::ArgMatches) -> Result<()> {

    if matches.is_present("list") {
        println!("list");
        match ctap_hid_fido2::get_info(&HidParam::get_default_params()) {
            Ok(info) => {
                println!("{}", info);
            }
            Err(err) => return Err(err),
        };
    }

    if matches.is_present("option") {
        let mut values = matches.values_of("option").unwrap();
        let typ = values.next().unwrap();

        let info_option = match typ {
            "rk" => InfoOption::Rk,
            "up" => InfoOption::Up,
            "uv" => InfoOption::Uv,
            "plat" => InfoOption::Plat,
            "pin" => InfoOption::ClinetPin,
            "mgmtp" => InfoOption::CredentialMgmtPreview,
            "mgmt" => InfoOption::CredMgmt,
            "biop" => InfoOption::UserVerificationMgmtPreview,
            "bio" => InfoOption::BioEnroll,
            _ => return Err(anyhow!("Invalid option")),
        };
    
        match ctap_hid_fido2::enable_info_option(
            &HidParam::get_default_params(),
            info_option,
        ) {
            Ok(result) => println!("option {} = {:?}",typ, result),
            Err(err) => return Err(err),
        }
    
    }

    if matches.is_present("param") {
        let mut values = matches.values_of("param").unwrap();
        let typ = values.next().unwrap();

        let info_param = match typ {
            "u2f_v2" => InfoParam::VersionsU2Fv2,
            "fido2" => InfoParam::VersionsFido20,
            "fido21p" => InfoParam::VersionsFido21Pre,
            "fido21" => InfoParam::VersionsFido21,
            "hmac" => InfoParam::ExtensionsHmacSecret,
            _ => return Err(anyhow!("Invalid param")),
        };
    
        match ctap_hid_fido2::enable_info_param(
            &HidParam::get_default_params(),
            info_param,
        ) {
            Ok(result) => println!("param {} = {:?}",typ, result),
            Err(err) => return Err(err),
        }
    
    }

    Ok(())
}