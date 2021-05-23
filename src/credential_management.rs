use crate::client_pin;
use crate::credential_management_command;
use crate::credential_management_params;
use crate::credential_management_response;
use crate::ctaphid;
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::FidoKeyHid;
use crate::HidParam;

#[allow(unused_imports)]
use crate::util;

pub(crate) fn credential_management(
    hid_params: &[HidParam],
    pin: Option<&str>,
    sub_command: credential_management_command::SubCommand,
    rpid_hash: Option<Vec<u8>>,
    pkcd: Option<PublicKeyCredentialDescriptor>,
    pkcue: Option<PublicKeyCredentialUserEntity>,
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

    let send_payload = credential_management_command::create_payload(
        pin_token,
        sub_command,
        rpid_hash,
        pkcd,
        pkcue,
    );

    if util::is_debug() {
        println!("send(cbor) = {}", util::to_hex_str(&send_payload));
    }

    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;
    if util::is_debug() {
        println!("response(cbor) = {}", util::to_hex_str(&response_cbor));
    }

    credential_management_response::parse_cbor(&response_cbor)
}
