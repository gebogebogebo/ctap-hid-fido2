use anyhow::{anyhow, Error, Result};

use super::client_pin_command;
use super::client_pin_command::Permission;
use super::client_pin_command::SubCommand as PinCmd;
use super::client_pin_response;
use super::FidoKeyHid;

use crate::cose;
use crate::ctaphid;
use crate::enc_aes256_cbc;
use crate::enc_hmac_sha_256;
use crate::pintoken::PinToken;
use crate::ss::SharedSecret;

impl FidoKeyHid {
    pub fn get_authenticator_key_agreement(&self, cid: &[u8]) -> Result<cose::CoseKey> {
        let send_payload =
            client_pin_command::create_payload(PinCmd::GetKeyAgreement).map_err(Error::msg)?;
        let response_cbor = ctaphid::ctaphid_cbor(self, &cid, &send_payload).map_err(Error::msg)?;
        let authenticator_key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)
                .map_err(Error::msg)?;
        Ok(authenticator_key_agreement)
    }

    pub fn get_pin_token(&self, cid: &[u8], pin: &str) -> Result<PinToken> {
        if !pin.is_empty() {
            let authenticator_key_agreement = self.get_authenticator_key_agreement(cid)?;

            let shared_secret = SharedSecret::new(&authenticator_key_agreement).map_err(Error::msg)?;
            let pin_hash_enc = shared_secret.encrypt_pin(pin).map_err(Error::msg)?;

            let send_payload = client_pin_command::create_payload_get_pin_token(
                &shared_secret.public_key,
                &pin_hash_enc,
            );

            let response_cbor =
                ctaphid::ctaphid_cbor(&self, cid, &send_payload).map_err(Error::msg)?;

            // get pin_token (enc)
            let mut pin_token_enc =
                client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)
                    .map_err(Error::msg)?;

            // pintoken -> dec(pintoken)
            let pin_token_dec = shared_secret
                .decrypt_token(&mut pin_token_enc)
                .map_err(Error::msg)?;

            Ok(pin_token_dec)
        } else {
            Err(anyhow!("pin not set"))
        }
    }

    pub fn get_pinuv_auth_token_with_permission(
        &self,
        cid: &[u8],
        pin: &str,
        permission: Permission,
    ) -> Result<PinToken> {
        if !pin.is_empty() {
            let authenticator_key_agreement = self.get_authenticator_key_agreement(&cid)?;

            // Get pinHashEnc
            // - shared_secret.public_key -> platform KeyAgreement
            let shared_secret = SharedSecret::new(&authenticator_key_agreement).map_err(Error::msg)?;
            let pin_hash_enc = shared_secret.encrypt_pin(pin).map_err(Error::msg)?;

            // Get pin token
            let send_payload =
                client_pin_command::create_payload_get_pin_uv_auth_token_using_pin_with_permissions(
                    &shared_secret.public_key,
                    &pin_hash_enc,
                    permission,
                );
            let response_cbor =
                ctaphid::ctaphid_cbor(&self, &cid, &send_payload).map_err(Error::msg)?;

            // get pin_token (enc)
            let mut pin_token_enc =
                client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)
                    .map_err(Error::msg)?;

            // pintoken -> dec(pintoken)
            let pin_token_dec = shared_secret
                .decrypt_token(&mut pin_token_enc)
                .map_err(Error::msg)?;

            Ok(pin_token_dec)
        } else {
            Err(anyhow!("pin not set"))
        }
    }

    pub fn set_pin(&self, cid: &[u8], pin: &str) -> Result<()> {
        if pin.is_empty() {
            return Err(anyhow!("new pin not set"));
        }

        let send_payload =
            client_pin_command::create_payload(PinCmd::GetKeyAgreement).map_err(Error::msg)?;
        let response_cbor = ctaphid::ctaphid_cbor(&self, cid, &send_payload).map_err(Error::msg)?;

        let key_agreement = client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)
            .map_err(Error::msg)?;

        let shared_secret = SharedSecret::new(&key_agreement).map_err(Error::msg)?;

        let new_pin_enc = create_new_pin_enc(&shared_secret, pin)?;

        let pin_auth = create_pin_auth_for_set_pin(&shared_secret, &new_pin_enc)?;

        let send_payload = client_pin_command::create_payload_set_pin(
            &shared_secret.public_key,
            &pin_auth,
            &new_pin_enc,
        );

        ctaphid::ctaphid_cbor(&self, cid, &send_payload).map_err(Error::msg)?;

        Ok(())
    }
}

// pinAuth = LEFT(HMAC-SHA-256(sharedSecret, newPinEnc), 16)
fn create_pin_auth_for_set_pin(
    shared_secret: &SharedSecret,
    new_pin_enc: &[u8],
) -> Result<Vec<u8>> {
    // HMAC-SHA-256(sharedSecret, newPinEnc)
    let sig = enc_hmac_sha_256::authenticate(&shared_secret.secret, new_pin_enc);

    // left 16
    let pin_auth = sig[0..16].to_vec();

    Ok(pin_auth)
}

fn create_pin_auth_for_change_pin(
    shared_secret: &SharedSecret,
    new_pin_enc: &[u8],
    current_pin_hash_enc: &[u8],
) -> Result<Vec<u8>> {
    // source data
    let mut message = vec![];
    message.append(&mut new_pin_enc.to_vec());
    message.append(&mut current_pin_hash_enc.to_vec());

    // HMAC-SHA-256(sharedSecret, message)
    let sig = enc_hmac_sha_256::authenticate(&shared_secret.secret, &message);

    // left 16
    let pin_auth = sig[0..16].to_vec();

    Ok(pin_auth)
}

fn padding_pin_64(pin: &str) -> Result<Vec<u8>> {
    // 5.5.5. Setting a New PIN
    // 5.5.6. Changing existing PIN
    // During encryption,
    // newPin is padded with trailing 0x00 bytes and is of minimum 64 bytes length.
    // This is to prevent leak of PIN length while communicating to the authenticator.
    // There is no PKCS #7 padding used in this scheme.

    let mut bpin64: Vec<u8> = vec![0; 64];
    let pintmp = pin.as_bytes();

    for (i, val) in pintmp.iter().enumerate() {
        bpin64[i] = *val;
    }

    Ok(bpin64)
}

// newPinEnc: AES256-CBC(sharedSecret, IV = 0, newPin)
fn create_new_pin_enc(shared_secret: &SharedSecret, new_pin: &str) -> Result<Vec<u8>> {
    let new_pin_64 = padding_pin_64(new_pin)?;

    let new_pin_enc = enc_aes256_cbc::encrypt_message(&shared_secret.secret, &new_pin_64);

    Ok(new_pin_enc)
}

pub fn change_pin(device: &FidoKeyHid, cid: &[u8], current_pin: &str, new_pin: &str) -> Result<()> {
    if current_pin.is_empty() {
        return Err(anyhow!("current pin not set"));
    }
    if new_pin.is_empty() {
        return Err(anyhow!("new pin not set"));
    }

    let send_payload =
        client_pin_command::create_payload(PinCmd::GetKeyAgreement).map_err(Error::msg)?;
    let response_cbor = ctaphid::ctaphid_cbor(device, cid, &send_payload).map_err(Error::msg)?;

    let key_agreement = client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)
        .map_err(Error::msg)?;

    let shared_secret = SharedSecret::new(&key_agreement).map_err(Error::msg)?;

    let new_pin_enc = create_new_pin_enc(&shared_secret, new_pin)?;

    let current_pin_hash_enc = shared_secret.encrypt_pin(current_pin).map_err(Error::msg)?;

    let pin_auth =
        create_pin_auth_for_change_pin(&shared_secret, &new_pin_enc, &current_pin_hash_enc)?;

    let send_payload = client_pin_command::create_payload_change_pin(
        &shared_secret.public_key,
        &pin_auth,
        &new_pin_enc,
        &current_pin_hash_enc,
    );

    ctaphid::ctaphid_cbor(device, cid, &send_payload).map_err(Error::msg)?;

    Ok(())
}
