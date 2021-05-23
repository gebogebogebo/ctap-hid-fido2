use crate::client_pin;
use crate::ctaphid;
use crate::enc_hmac_sha_256;
use crate::get_assertion_command;
use crate::get_assertion_params::Assertion;
use crate::get_assertion_params::Extension as Gext;
use crate::get_assertion_response;
use crate::get_next_assertion_command;
use crate::hmac::HmacExt;
#[allow(unused_imports)]
use crate::util;
use crate::FidoKeyHid;
use crate::HidParam;
use anyhow::{Error, Result};

pub fn get_assertion(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    credential_id: &[u8],
    pin: Option<&str>,
    up: bool,
    uv: Option<bool>,
    extensions: Option<&Vec<Gext>>,
) -> Result<Vec<Assertion>> {
    // init
    let device = FidoKeyHid::new(hid_params).map_err(Error::msg)?;
    let cid = ctaphid::ctaphid_init(&device).map_err(Error::msg)?;

    /*
    // uv
    let uv = {
        match pin {
            Some(_) => false,
            None => true,
        }
    };
    */

    let hmac_ext = create_hmacext(&device, &cid, extensions)?;

    // pin token
    let pin_token = {
        if let Some(pin) = pin {
            //let shared_secret = client_pin::get_shared_secret(&device, &cid, pin).map_err(Error::msg)?;
            //Some(client_pin::get_pin_token2(&shared_secret, &device, &cid, pin).map_err(Error::msg)?)
            Some(client_pin::get_pin_token(&device, &cid, pin).map_err(Error::msg)?)
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
            let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &params.client_data_hash);
            params.pin_auth = sig[0..16].to_vec();
        }

        get_assertion_command::create_payload(params, hmac_ext)
    };
    util::debugp("- get_assertion", &send_payload);

    // send & response
    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload).map_err(Error::msg)?;
    util::debugp("- response_cbor", &response_cbor);

    let ass = get_assertion_response::parse_cbor(&response_cbor).map_err(Error::msg)?;

    let mut asss = vec![ass];
    for _ in 0..(asss[0].number_of_credentials - 1) {
        let ass = get_next_assertion(&device, &cid).map_err(Error::msg)?;
        asss.push(ass);
    }

    Ok(asss)
}

fn get_next_assertion(device: &FidoKeyHid, cid: &[u8]) -> Result<Assertion, String> {
    let send_payload = get_next_assertion_command::create_payload();
    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;
    get_assertion_response::parse_cbor(&response_cbor)
}

fn create_hmacext(
    device: &FidoKeyHid,
    cid: &[u8; 4],
    extensions: Option<&Vec<Gext>>,
) -> Result<Option<HmacExt>> {
    if let Some(extensions) = extensions {
        for ext in extensions {
            match ext {
                Gext::HmacSecret(n) => {
                    let mut hmac_ext = HmacExt::default();
                    hmac_ext.create(device, cid, &n.unwrap(), None)?;
                    return Ok(Some(hmac_ext));
                }
            }
        }
        Ok(None)
    } else {
        Ok(None)
    }
}
