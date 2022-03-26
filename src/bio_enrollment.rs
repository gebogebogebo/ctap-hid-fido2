use crate::bio_enrollment_command;
use crate::bio_enrollment_params::{BioEnrollmentData, TemplateInfo};
use crate::bio_enrollment_response;
use crate::ctaphid;
use crate::pintoken::PinToken;
use crate::{
    FidoKeyHid,
    fidokey::pin::Permission,
};

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
            if device.use_pre_bio_enrollment {
                Some(device.get_pin_token(&cid, pin)?)
            } else {
                Some(device.get_pinuv_auth_token_with_permission(
                    &cid,
                    pin,
                    Permission::Be,
                )?)
            }
        } else {
            None
        }
    };

    Ok((cid, pin_token))
}
