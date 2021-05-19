use crate::client_pin_command;
use crate::client_pin_response;
use crate::ctaphid;
use crate::pintoken;
use crate::ss;
#[allow(unused_imports)]
use crate::util;
use crate::FidoKeyHid;
use crate::client_pin_command::SubCommand as PinCmd;

pub fn get_pin_token(
    device: &FidoKeyHid,
    cid: &[u8],
    pin: &str,
) -> Result<pintoken::PinToken, String> {
    if !pin.is_empty() {
        let send_payload =
            client_pin_command::create_payload(PinCmd::GetKeyAgreement)?;
        let response_cbor = ctaphid::ctaphid_cbor(device, cid, &send_payload)?;

        let key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

        let shared_secret = ss::SharedSecret::new(&key_agreement)?;
        let pin_hash_enc = shared_secret.encrypt_pin(pin)?;

        let send_payload = client_pin_command::create_payload_get_pin_token(
            &shared_secret.public_key,
            pin_hash_enc.to_vec(),
        );

        let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;

        // get pin_token (enc)
        let mut pin_token_enc =
            client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;

        // pintoken -> dec(pintoken)
        let pin_token_dec = shared_secret.decrypt_token(&mut pin_token_enc)?;

        Ok(pin_token_dec)
    } else {
        Err("pin not set".to_string())
    }
}

// PEND
pub fn get_data(
    device: &FidoKeyHid,
    cid: &[u8],
    salt: &[u8; 32],
    salt2: Option<&[u8; 32]>
) -> Result<(), String> {
    let send_payload =
        client_pin_command::create_payload(PinCmd::GetKeyAgreement)?;
    let response_cbor = ctaphid::ctaphid_cbor(device, cid, &send_payload)?;

    let key_agreement =
        client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

    let shared_secret = ss::SharedSecret::new(&key_agreement)?;
    Ok(())
}
