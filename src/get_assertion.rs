#[allow(unused_imports)]
use crate::util;
use crate::get_assertion_command;
use crate::get_assertion_params;
use crate::get_assertion_response;
use crate::ctaphid;
use crate::get_pin_token;
use crate::FidoKeyHid;
use crate::HidParam;

pub fn get_assertion_inter(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    credential_id: &[u8],
    pin: Option<&str>,
    up: bool,
) -> Result<Vec<get_assertion_params::Assertion>, String> {
    // init
    let device = FidoKeyHid::new(hid_params)?;
    let cid = ctaphid::ctaphid_init(&device)?;

    // uv
    let uv = {
        match pin {
            Some(_) => false,
            None => true,
        }
    };

    // pin token
    let pin_token = {
        if let Some(pin) = pin {
            Some(get_pin_token(&device, &cid, pin.to_string())?)
        } else {
            None
        }
    };

    //let pin_token = get_pin_token(&device, &cid, pin.to_string())?;

    // create cmmand
    let send_payload = {
        let mut params =
            get_assertion_command::Params::new(rpid, challenge.to_vec(), credential_id.to_vec());
        params.option_up = up;
        params.option_uv = uv;

        // create pin auth
        if let Some(pin_token) = pin_token {
            let pin_auth = pin_token.authenticate_v1(&params.client_data_hash);
            //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));
            params.pin_auth = pin_auth.to_vec();
        }

        get_assertion_command::create_payload(params)
    };
    //println!("- get_assertion({:02})    = {:?}", send_payload.len(),util::to_hex_str(&send_payload));

    // send & response
    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;

    if util::is_debug() == true {
        println!(
            "- response_cbor({:02})    = {:?}",
            response_cbor.len(),
            util::to_hex_str(&response_cbor)
        );
    }

    let ass = get_assertion_response::parse_cbor(&response_cbor)?;

    let mut asss = vec![ass];

    for _ in 0..(asss[0].number_of_credentials - 1) {
        let ass = crate::get_next_assertion(&device, &cid)?;
        asss.push(ass);
    }

    Ok(asss)
}
