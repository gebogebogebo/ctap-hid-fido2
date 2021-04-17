use crate::client_pin;
use crate::bio_enrollment_command;
//use crate::credential_management_params;
//use crate::credential_management_response;
use crate::ctaphid;
use crate::FidoKeyHid;
use crate::HidParam;

#[allow(unused_imports)]
use crate::util;

pub fn bio_enrollment(
    hid_params: &[HidParam],
    pin: Option<&str>,
    sub_command: Option<bio_enrollment_command::SubCommand>,
) -> Result<String, String> {

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
 
    let _send_payload = bio_enrollment_command::create_payload(
        pin_token,
        sub_command,
    );

    Ok("".to_string())
}
