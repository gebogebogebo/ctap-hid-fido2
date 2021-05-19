use crate::client_pin_command;
use crate::client_pin_response;
use crate::ctaphid;
use crate::pintoken;
use crate::ss;
#[allow(unused_imports)]
use crate::util;
use crate::FidoKeyHid;
use crate::client_pin_command::SubCommand as PinCmd;

use ring::{digest, hmac};
use pintoken::PinToken;

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
    salt1: &[u8; 32],
    salt2: Option<&[u8; 32]>
) -> Result<(), String> {
    let send_payload =
        client_pin_command::create_payload(PinCmd::GetKeyAgreement)?;
    let response_cbor = ctaphid::ctaphid_cbor(device, cid, &send_payload)?;

    let key_agreement =
        client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

    let shared_secret = ss::SharedSecret::new(&key_agreement)?;

    // https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-hmac-secret-extension

    // saltEnc(0x02)
    //  Encryption of the one or two salts (called salt1 (32 bytes) 
    //  and salt2 (32 bytes)) using the shared secret as follows
    // One salt case: encrypt(shared secret, salt1)
    // Two salt case: encrypt(shared secret, salt1 || salt2)
    //  encrypt(key, demPlaintext) → ciphertext
    //      Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext. 
    //      The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
    let salt_enc = shared_secret.encrypt(salt1)?;


    // saltAuth(0x03)
    //  authenticate(shared secret, saltEnc)
    //   authenticate(key, message) → signature
    let pin_token = pintoken::PinToken {
        signing_key: hmac::SigningKey::new(&digest::SHA256, &salt_enc),
        key: salt_enc.to_vec(),
    };

    let salt_auth = pin_token.authenticate_v2(&salt_enc, 16);



    Ok(())
}
