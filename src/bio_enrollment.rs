use crate::bio_enrollment_command;
use crate::client_pin;
use crate::bio_enrollment_params::BioEnrollmentData;
use crate::bio_enrollment_response;
use crate::ctaphid;
use crate::FidoKeyHid;
use crate::HidParam;

#[allow(unused_imports)]
use crate::util;

pub(crate) fn bio_enrollment(
    hid_params: &[HidParam],
    pin: Option<&str>,
    sub_command: Option<bio_enrollment_command::SubCommand>,
) -> Result<BioEnrollmentData, String> {
    // init
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

    let send_payload = bio_enrollment_command::create_payload(pin_token, sub_command);

    if util::is_debug() == true {
        println!("send(cbor) = {}", util::to_hex_str(&send_payload));
    }

    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;
    if util::is_debug() == true {
        println!("response(cbor) = {}", util::to_hex_str(&response_cbor));
    }

    let ret = bio_enrollment_response::parse_cbor(&response_cbor)?;

    Ok(ret)
}
