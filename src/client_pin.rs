use crate::client_pin_command;
use crate::client_pin_response;
use crate::ctaphid;
use crate::pintoken;
use crate::ss;
#[allow(unused_imports)]
use crate::util;
use crate::FidoKeyHid;

pub fn get_pin_token(
    device: &FidoKeyHid,
    cid: &[u8],
    pin: String,
) -> Result<pintoken::PinToken, String> {
    if pin.len() > 0 {
        let send_payload =
            client_pin_command::create_payload(client_pin_command::SubCommand::GetKeyAgreement)?;
        let response_cbor = ctaphid::ctaphid_cbor(device, cid, &send_payload)?;

        let key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

        let shared_secret = ss::SharedSecret::new(&key_agreement)?;
        //shared_secret.public_key.print("SharedSecret  - Public Key");

        let pin_hash_enc = shared_secret.encrypt_pin(&pin)?;
        //println!("- PIN hash enc({:?})       = {:?}", pin_hash_enc.len(), util::to_hex_str(&pin_hash_enc));

        let send_payload = client_pin_command::create_payload_get_pin_token(
            &shared_secret.public_key,
            pin_hash_enc.to_vec(),
        );

        let response_cbor = ctaphid::ctaphid_cbor(&device, &cid, &send_payload)?;

        // get pin_token (enc)
        let mut pin_token_enc =
            client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;
        //println!("- pin_token_enc({:?})       = {:?}", pin_token_enc.len(), util::to_hex_str(&pin_token_enc));

        // pintoken -> dec(pintoken)
        let pin_token_dec = shared_secret.decrypt_token(&mut pin_token_enc)?;
        //println!("- pin_token_dec({:?})       = {:?}", pin_token_dec.len(), util::to_hex_str(&pin_token_dec));

        Ok(pin_token_dec)
    } else {
        Err("pin not set".to_string())
    }
}
