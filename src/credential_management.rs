use crate::client_pin;
use crate::credential_management_command;
use crate::credential_management_params;
use crate::credential_management_response;
use crate::ctaphid;
use crate::FidoKeyHid;
use crate::HidParam;

#[allow(unused_imports)]
use crate::util;

pub(crate) fn credential_management(
    hid_params: &[HidParam],
    pin: Option<&str>,
    sub_command: credential_management_command::SubCommand,
    rpid_hash: Option<Vec<u8>>,
    pkcd: Option<credential_management_params::PublicKeyCredentialDescriptor>,
    pkcue: Option<credential_management_params::PublicKeyCredentialUserEntity>,
) -> Result<credential_management_params::CredentialManagementData, String> {
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;

    // pin token
    let pin_token = {
        if let Some(pin) = pin {
            Some(client_pin::get_pin_token(&device, &cid, pin)?)
        } else {
            None
        }
    };

    //if let Some(pin_token) = pin_token {
        let send_payload = credential_management_command::create_payload(
            pin_token,
            sub_command,
            rpid_hash,
            pkcd,
            pkcue,
        );

        if util::is_debug() == true {
            println!("send(cbor) = {}",util::to_hex_str(&send_payload));
        }

        let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;
        if util::is_debug() == true {
            println!("response(cbor) = {}",util::to_hex_str(&response_cbor));
        }

        Ok(credential_management_response::parse_cbor(&response_cbor)?)
    //} else {
    //    Err("PIN Token Error".to_string())
    //}
}
