use anyhow::{anyhow, Result};
use ctap_hid_fido2::{InfoOption, InfoParam};
use crate::CFG;
use crate::str_buf::StrBuf;

pub fn info(matches: &clap::ArgMatches) -> Result<()> {
    if matches.args.is_empty() {
        println!("Get all data.");
        match ctap_hid_fido2::get_info(&CFG) {
            Ok(info) => println!("{}", info),
            Err(err) => return Err(err),
        };
    }

    if matches.is_present("get") {
        let mut values = matches.values_of("get").unwrap();
        let item = values.next().unwrap();

        let info_option = match item {
            "rk" => Some(InfoOption::Rk),
            "up" => Some(InfoOption::Up),
            "uv" => Some(InfoOption::Uv),
            "plat" => Some(InfoOption::Plat),
            "pin" => Some(InfoOption::ClinetPin),
            "mgmtp" => Some(InfoOption::CredentialMgmtPreview),
            "mgmt" => Some(InfoOption::CredMgmt),
            "biop" => Some(InfoOption::UserVerificationMgmtPreview),
            "bio" => Some(InfoOption::BioEnroll),
            _ => None,
        };

        if let Some(option) = info_option {
            match ctap_hid_fido2::enable_info_option(&CFG, &option) {
                Ok(result) => println!("{}", option_message(item, &option, result)?),
                Err(err) => return Err(err),
            }
        } else {
            let info_param = match item {
                "u2f_v2" => Some(InfoParam::VersionsU2Fv2),
                "fido2" => Some(InfoParam::VersionsFido20),
                "fido21p" => Some(InfoParam::VersionsFido21Pre),
                "fido21" => Some(InfoParam::VersionsFido21),
                "hmac" => Some(InfoParam::ExtensionsHmacSecret),
                _ => None,
            };

            if let Some(param) = info_param {
                match ctap_hid_fido2::enable_info_param(&CFG, &param) {
                    Ok(result) => println!("{}", param_message(item, &param, result)?),
                    Err(err) => return Err(err),
                }
            } else {
                return Err(anyhow!("Invalid item"));
            }
        }
    }

    Ok(())
}

fn option_message(typ: &str, info_option: &InfoOption, val: Option<bool>) -> Result<String> {
    let value_str = match val {
        Some(v) => format!("{}", v),
        None => "Not Supported".to_string(),
    };
    let message1 = format!("option {} = {}", typ, value_str);

    let message2 = match info_option {
        InfoOption::Rk => {
            let mut strbuf = StrBuf::new(0);
            strbuf.addln("rk(resident key)");

            if val.is_some() && val.unwrap() {
                strbuf.addln("This authenticator can create discoverable credentials.");
            } else {
                strbuf.addln("This authenticator can not create discoverable credentials.");
            }

            strbuf
                .addln("")
                .addln("Discoverable credentials")
                .addln("https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-discoverable");
            strbuf.build().to_string()
        }
        InfoOption::Up => {
            let mut strbuf = StrBuf::new(0);
            strbuf.addln("up(user presence)");

            if val.is_some() && val.unwrap() {
                strbuf.addln("This authenticator is capable of testing user presence.");
            } else {
                strbuf.addln("This authenticator is not capable of testing user presence.");
            }
            strbuf.addln("User presence is confirmed by a button or touch sensor.");
            strbuf.build().to_string()
        }
        InfoOption::Uv => {
            let mut strbuf = StrBuf::new(0);
            strbuf.addln("uv(user verification)");

            if val.is_some() && val.unwrap() {
                strbuf.addln("This authenticator supports a built-in user verification method.");
            } else if val.is_some() && !val.unwrap() {
                strbuf.addln("This authenticator supports a built-in user verification method but its user verification feature is not presently configured.");
            } else {
                strbuf
                    .addln("This authenticator not supports a built-in user verification method.");
            }
            strbuf.addln("For example, devices with UI, biometrics fall into this category.");
            strbuf.build().to_string()
        }
        InfoOption::ClinetPin => {
            let mut strbuf = StrBuf::new(0);

            if val.is_some() && val.unwrap() {
                strbuf.addln("This authenticator is capable of accepting a PIN from the client and PIN has been set.");
            } else if val.is_some() && !val.unwrap() {
                strbuf.addln("This authenticator is capable of accepting a PIN from the client and PIN has not been set yet.");
            } else {
                strbuf
                    .addln("This authenticator is not capable of accepting a PIN from the client.");
            }
            strbuf.build().to_string()
        }
        InfoOption::Plat => {
            let mut strbuf = StrBuf::new(0);
            strbuf.addln("plat(platform device)");

            if val.is_some() && val.unwrap() {
                strbuf.addln("This authenticator is attached to the client and therefore can’t be removed and used on another client.");
            } else {
                strbuf.addln("This authenticator can be removed and used on another client.");
            }
            strbuf.build().to_string()
        }
        InfoOption::UserVerificationMgmtPreview | InfoOption::BioEnroll => {
            let mut strbuf = StrBuf::new(0);
            strbuf.addln("bioEnroll");

            if val.is_some() && val.unwrap() {
                strbuf.addln("This authenticator supports the authenticatorBioEnrollment commands, and has at least one bio enrollment presently provisioned.");
            } else if val.is_some() && !val.unwrap() {
                strbuf.addln("This authenticator supports the authenticatorBioEnrollment commands, and does not yet have any bio enrollments provisioned.");
            } else {
                strbuf.addln("The authenticatorBioEnrollment commands are NOT supported.");
            }
            strbuf.build().to_string()
        }
        InfoOption::CredMgmt | InfoOption::CredentialMgmtPreview => {
            let mut strbuf = StrBuf::new(0);
            strbuf.addln("Credential management support");

            if val.is_some() && val.unwrap() {
                strbuf.addln("This authenticatorCredentialManagement command is supported.");
            } else {
                strbuf.addln("The authenticatorCredentialManagement commands are NOT supported.");
            }
            strbuf.build().to_string()
        }
        //_ => "".to_string(),
    };
    Ok(format!("{}\n\n{}", message1, message2))
}

fn param_message(typ: &str, info_param: &InfoParam, val: bool) -> Result<String> {
    let message1 = format!("option {} = {}", typ, val);

    let message2 = match info_param {
        InfoParam::VersionsU2Fv2 => {
            let mut strbuf = StrBuf::new(0);
            if val {
                strbuf.addln("This authenticator is supported CTAP1/U2F.");
            } else {
                strbuf.addln("This authenticator is not supported CTAP1/U2F.");
            }
            strbuf.build().to_string()
        }
        InfoParam::VersionsFido20 => {
            let mut strbuf = StrBuf::new(0);
            if val {
                strbuf.addln("This is CTAP2.0 / FIDO2 / Web Authentication authenticators.");
            } else {
                strbuf.addln("This is not CTAP2.0 / FIDO2 / Web Authentication authenticators.");
            }
            strbuf.build().to_string()
        }
        InfoParam::VersionsFido21Pre => {
            let mut strbuf = StrBuf::new(0);
            if val {
                strbuf.addln("This authenticator is supported CTAP2.1 Preview features.");
            } else {
                strbuf.addln("This authenticator is not supported CTAP2.1 Preview features.");
            }
            strbuf.build().to_string()
        }
        InfoParam::VersionsFido21 => {
            let mut strbuf = StrBuf::new(0);
            if val {
                strbuf.addln(
                    "This is CTAP2.1 / FIDO2(lelvel2) / Web Authentication(level2) authenticators.",
                );
            } else {
                strbuf.addln("This is not CTAP2.1 / FIDO2(lelvel2) / Web Authentication(level2) authenticators.");
            }
            strbuf.build().to_string()
        }
        InfoParam::ExtensionsHmacSecret => {
            let mut strbuf = StrBuf::new(0);
            strbuf.addln("hmac(HMAC Secret Extension)");

            if val {
                strbuf.addln("This authenticator is supported HMAC Secret Extension.");
            } else {
                strbuf.addln("This authenticator is not supported HMAC Secret Extension.");
            }

            strbuf
                .addln("")
                .addln("HMAC Secret Extension")
                .addln("https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-hmac-secret-extension");

            strbuf.build().to_string()
        }
        _ => "".to_string(),
    };

    Ok(format!("{}\n\n{}", message1, message2))
}
