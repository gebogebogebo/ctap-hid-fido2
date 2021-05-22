use crate::client_pin;
use crate::ctaphid;
use crate::make_credential_command;
use crate::make_credential_params;
use crate::make_credential_params::Extension;
use crate::make_credential_response;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::FidoKeyHid;
use crate::HidParam;

#[allow(unused_imports)]
use crate::util;

pub fn make_credential(
    hid_params: &[HidParam],
    rpid: &str,
    challenge: &[u8],
    pin: Option<&str>,
    rk: bool,
    rkparam: Option<&PublicKeyCredentialUserEntity>,
    uv: Option<bool>,
    extensions: Option<&Vec<Extension>>,
) -> Result<make_credential_params::Attestation, String> {
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
        //println!("- client_data_hash({:02})    = {:?}", params.client_data_hash.len(),util::to_hex_str(&params.client_data_hash));

        // get pintoken & create pin auth
        if let Some(pin) = pin {
            if !pin.is_empty() {
                let pin_auth = client_pin::get_pin_token(&device, &cid, pin)?
                    .authenticate_v1(&params.client_data_hash);

                //println!("- pin_auth({:02})    = {:?}", pin_auth.len(),util::to_hex_str(&pin_auth));
                params.pin_auth = pin_auth.to_vec();
            }
        }

        make_credential_command::create_payload(params, extensions)
    };
    util::debugp("- make_credential", &send_payload);

    // send & response
    let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;
    util::debugp("- response_cbor", &response_cbor);

    let att = make_credential_response::parse_cbor(&response_cbor)?;
    Ok(att)
}
