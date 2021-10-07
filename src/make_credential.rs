use crate::client_pin;
use crate::ctaphid;
use crate::enc_hmac_sha_256;
use crate::make_credential_command;
use crate::make_credential_params;
use crate::make_credential_params::Extension;
use crate::make_credential_response;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::FidoKeyHid;

#[allow(unused_imports)]
use crate::util;

pub fn make_credential(
    device: &FidoKeyHid,
    rpid: &str,
    challenge: &[u8],
    pin: Option<&str>,
    rk: bool,
    rkparam: Option<&PublicKeyCredentialUserEntity>,
    uv: Option<bool>,
    extensions: Option<&Vec<Extension>>,
) -> Result<make_credential_params::Attestation, String> {
    // init
    let cid = ctaphid::ctaphid_init(device)?;

    /*
    // uv
    let uv = {
        match pin {
            Some(_) => false,
            None => true,
        }
    };
    */

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

        if let Some(rkp) = rkparam {
            params.user_name = rkp.name.to_string();
            params.user_display_name = rkp.display_name.to_string();
        }

        // get pintoken & create pin auth
        if let Some(pin) = pin {
            if !pin.is_empty() {
                let pin_token = client_pin::get_pin_token(device, &cid, pin)?;
                let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &params.client_data_hash);
                params.pin_auth = sig[0..16].to_vec();
            }
        }

        make_credential_command::create_payload(params, extensions)
    };
    util::debugp("- make_credential", &send_payload);

    // send & response
    let response_cbor = ctaphid::ctaphid_cbor(device, &cid, &send_payload)?;
    util::debugp("- response_cbor", &response_cbor);

    let att = make_credential_response::parse_cbor(&response_cbor)?;
    Ok(att)
}
