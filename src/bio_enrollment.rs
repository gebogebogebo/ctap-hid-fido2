use crate::bio_enrollment_command;
use crate::bio_enrollment_params::{BioEnrollmentData, TemplateInfo};
use crate::bio_enrollment_response;
use crate::client_pin;
use crate::ctaphid;
use crate::client_pin_command;
use crate::client_pin_command::Permission;
use crate::client_pin_command::SubCommand as PinCmd;
use crate::pintoken::PinToken;
use crate::FidoKeyHid;
use crate::client_pin_response;
use crate::ss::SharedSecret;

#[allow(unused_imports)]
use crate::util;

use anyhow::{Error, Result};

pub(crate) fn bio_enrollment(
    device: &FidoKeyHid,
    cid: &[u8; 4],
    pin_token: Option<&PinToken>,
    sub_command: Option<bio_enrollment_command::SubCommand>,
    template_info: Option<TemplateInfo>,
    timeout_milliseconds: Option<u16>,
) -> Result<BioEnrollmentData> {
    let send_payload = bio_enrollment_command::create_payload(
        pin_token,
        sub_command,
        template_info,
        timeout_milliseconds,
        device.use_pre_bio_enrollment,
    );

    if device.enable_log {
        println!("send(cbor) = {}", util::to_hex_str(&send_payload));
    }

    let response_cbor = ctaphid::ctaphid_cbor(device, cid, &send_payload).map_err(Error::msg)?;
    if device.enable_log {
        println!("response(cbor) = {}", util::to_hex_str(&response_cbor));
    }

    let ret = bio_enrollment_response::parse_cbor(&response_cbor).map_err(Error::msg)?;

    Ok(ret)
}

pub fn bio_enrollment_init(
    device: &FidoKeyHid,
    pin: Option<&str>,
) -> Result<([u8; 4], Option<PinToken>)> {
    // init
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;

    // pin token
    let pin_token = {
        if let Some(pin) = pin {

            /*
            // TODO
            // Get Device KeyAgreement
            let send_payload = client_pin_command::create_payload(PinCmd::GetKeyAgreement).map_err(Error::msg)?;
            let response_cbor = ctaphid::ctaphid_cbor(device, &cid, &send_payload).map_err(Error::msg)?;
            let key_agreement = client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)
            .map_err(Error::msg)?;

            // Get pinHashEnc
            // - shared_secret.public_key -> platform KeyAgreement
            let shared_secret = SharedSecret::new(&key_agreement).map_err(Error::msg)?;
            let pin_hash_enc = shared_secret.encrypt_pin(pin).map_err(Error::msg)?;

            let send_payload = client_pin_command::create_payload_get_pin_uv_auth_token_using_pin_with_permissions(
                &shared_secret.public_key,
                &pin_hash_enc,
                Permission::Be,
            );
            let response_cbor = ctaphid::ctaphid_cbor(device, &cid, &send_payload).map_err(Error::msg)?;

            // get pin_token (enc)
            let pin_token_enc =
                client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor).map_err(Error::msg)?;
            
            Some(PinToken::new(&pin_token_enc))
            // PEND
            */

            Some(client_pin::get_pin_token(device, &cid, pin)?)
        } else {
            None
        }
    };

    Ok((cid, pin_token))
}
