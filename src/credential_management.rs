use crate::credential_management_command;
use crate::credential_management_params;
use crate::credential_management_response;
use crate::ctaphid;
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::{
    FidoKeyHid,
    fidokey::pin::Permission,
};


#[allow(unused_imports)]
use crate::util;
use anyhow::{Error, Result};

pub(crate) fn credential_management(
    device: &FidoKeyHid,
    pin: Option<&str>,
    sub_command: credential_management_command::SubCommand,
    rpid_hash: Option<Vec<u8>>,
    pkcd: Option<PublicKeyCredentialDescriptor>,
    pkcue: Option<PublicKeyCredentialUserEntity>,
) -> Result<credential_management_params::CredentialManagementData> {
    let cid = ctaphid::ctaphid_init(device).map_err(Error::msg)?;

    // pin token
    let pin_token = {
        if let Some(pin) = pin {
            if device.use_pre_credential_management {
                Some(device.get_pin_token(&cid, pin)?)
            } else {
                Some(device.get_pinuv_auth_token_with_permission(
                    &cid,
                    pin,
                    Permission::Cm,
                )?)
            }
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
        device.use_pre_credential_management,
    );

    if device.enable_log {
        println!("send(cbor) = {}", util::to_hex_str(&send_payload));
    }

    let response_cbor = ctaphid::ctaphid_cbor(device, &cid, &send_payload).map_err(Error::msg)?;
    if device.enable_log {
        println!("response(cbor) = {}", util::to_hex_str(&response_cbor));
    }

    Ok(credential_management_response::parse_cbor(&response_cbor).map_err(Error::msg)?)
}
