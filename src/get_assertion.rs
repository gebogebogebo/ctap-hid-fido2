use crate::client_pin;
use crate::ctaphid;
use crate::get_assertion_command;
use crate::get_assertion_params;
use crate::get_assertion_response;
use crate::get_next_assertion_command;
#[allow(unused_imports)]
use crate::util;
use crate::FidoKeyHid;
use crate::HidParam;
use crate::get_assertion_params::Extension as Gext;

pub fn get_assertion(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    credential_id: &[u8],
    pin: Option<&str>,
    up: bool,
    uv: Option<bool>,
    extensions: Option<&Vec<Gext>>,
) -> Result<Vec<get_assertion_params::Assertion>, String> {
    // init
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;

    /*
    // uv
    let uv = {
        match pin {
            Some(_) => false,
            None => true,
        }
    };
    */

    if let Some(extensions) = extensions {
        for ext in extensions {
            match ext {
                Gext::HmacSecret(n) => {
                    let dmy : [u8;32] = Default::default();
                    client_pin::get_data(&device, &cid,&dmy,None)?;
                }
            }
        }
    };

    // pin token
    let pin_token = {
        if let Some(pin) = pin {
            Some(client_pin::get_pin_token(&device, &cid, pin)?)
        } else {
            None
        }
    };

    // create cmmand
    let send_payload = {
        let mut params =
            get_assertion_command::Params::new(rpid, challenge.to_vec(), credential_id.to_vec());
        params.option_up = up;
        params.option_uv = uv;

        // create pin auth
        if let Some(pin_token) = pin_token {
            let pin_auth = pin_token.authenticate_v1(&params.client_data_hash);
            params.pin_auth = pin_auth.to_vec();
        }

        get_assertion_command::create_payload(params)
    };
    util::debugp("- get_assertion",&send_payload);

    // send & response
    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;
    util::debugp("- response_cbor",&response_cbor);

    let ass = get_assertion_response::parse_cbor(&response_cbor)?;

    let mut asss = vec![ass];

    for _ in 0..(asss[0].number_of_credentials - 1) {
        let ass = get_next_assertion(&device, &cid)?;
        asss.push(ass);
    }

    Ok(asss)
}

fn get_next_assertion(
    device: &FidoKeyHid,
    cid: &[u8],
) -> Result<get_assertion_params::Assertion, String> {
    let send_payload = get_next_assertion_command::create_payload();
    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;
    get_assertion_response::parse_cbor(&response_cbor)
}
