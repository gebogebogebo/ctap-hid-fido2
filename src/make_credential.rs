use crate::ctaphid;
use crate::enc_hmac_sha_256;
use crate::make_credential_command;
use crate::make_credential_params;
use crate::make_credential_params::{CredentialSupportedKeyType, Extension};
use crate::make_credential_response;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::FidoKeyHid;

#[allow(unused_imports)]
use crate::util;

use anyhow::{Error, Result};

pub fn make_credential(
    device: &FidoKeyHid,
    rpid: &str,
    challenge: &[u8],
    pin: Option<&str>,
    rk: bool,
    rkparam: Option<&PublicKeyCredentialUserEntity>,
    //uv: Option<bool>,
    extensions: Option<&Vec<Extension>>,
    key_type: Option<CredentialSupportedKeyType>,
) -> Result<make_credential_params::Attestation> {
    // init
    let cid = ctaphid::ctaphid_init(device).map_err(Error::msg)?;

    // uv
    let uv = {
        match pin {
            Some(_) => None,
            None => Some(true),
        }
    };

    let user_id = {
        if let Some(rkp) = rkparam {
            rkp.id.to_vec()
        } else {
            [].to_vec()
        }
    };

    // create cmmand
    let send_payload = {
        let mut params = make_credential_command::Params::new(rpid, challenge.to_vec(), user_id);
        params.option_rk = rk;
        params.option_uv = uv;
        params.key_type = key_type.unwrap_or(CredentialSupportedKeyType::Ecdsa256);

        if let Some(rkp) = rkparam {
            params.user_name = rkp.name.to_string();
            params.user_display_name = rkp.display_name.to_string();
        }

        // get pintoken & create pin auth
        if let Some(pin) = pin {
            if !pin.is_empty() {
                let pin_token = device.get_pin_token(&cid, pin)?;
                let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &params.client_data_hash);
                params.pin_auth = sig[0..16].to_vec();
            }
        }

        make_credential_command::create_payload(params, extensions)
    };

    // send & response
    let response_cbor = ctaphid::ctaphid_cbor(device, &cid, &send_payload).map_err(Error::msg)?;

    let att = make_credential_response::parse_cbor(&response_cbor).map_err(Error::msg)?;
    Ok(att)
}
