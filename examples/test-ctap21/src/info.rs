use ctap_hid_fido2;
use anyhow::{anyhow,Result};
use crate::str_buf::StrBuf;

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

        // RK
        // Resident Key
        // true
        // this authenticator can create discoverable credentials
        // false
        // this authenticator can not create discoverable credentials
        //
        // Discoverable credentials
        // https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-discoverable
    
        match ctap_hid_fido2::enable_info_option(
            &HidParam::get_default_params(),
            info_option.clone(),
        ) {
            Ok(result) => {
                let a = option_message(typ,&info_option,result)?;
                println!("{}",a);
                //println!("option {} = {:?}",typ, result);
            },
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

fn option_message(typ: &str, info_option: &InfoOption, val: Option<bool>) -> Result<String> {
    let value_str = match val {
        Some(v) => format!("{}", v),
        None => format!("Not Supported"),
    };
    let message1 = format!("option {} = {}",typ, value_str);

    let message2 = match info_option {
        InfoOption::Rk => {
            let mut strbuf = StrBuf::new(0);
            strbuf.add("- rk(Resident Key)\n");
            if true {
                strbuf.add("- this authenticator can create discoverable credentials");
            }else{
                strbuf.add("- this authenticator can not create discoverable credentials");
            }
            strbuf
                .add("- Discoverable credentials")
                .add("https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-discoverable");
            strbuf.build().to_string()
        },

        /*
        InfoOption::Up => "up",
        InfoOption::Uv => "uv",
        InfoOption::Plat => "plat",
        InfoOption::ClinetPin => "clientPin",
        InfoOption::CredentialMgmtPreview => "credentialMgmtPreview",
        InfoOption::CredMgmt => "credMgmt",
        InfoOption::UserVerificationMgmtPreview => "userVerificationMgmtPreview",
        InfoOption::BioEnroll => "bioEnroll",
        */
        _ => "a".to_string()
    };
    Ok(format!("{}\n\n{}",message1,message2))
}