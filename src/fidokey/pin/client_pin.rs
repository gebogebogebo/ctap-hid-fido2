use super::client_pin_command;
use super::client_pin_command::Permission;
use super::client_pin_command::SubCommand as PinCmd;
use super::client_pin_response;
use super::FidoKeyHid;
use crate::ctaphid;
use crate::encrypt::cose;
use crate::pin_uv_auth_protocol::{compute_pin_uv_auth_param, PinUvAuthSharedSecret};
use crate::pintoken::PinToken;
use anyhow::{anyhow, Result};

impl FidoKeyHid {
    pub fn get_authenticator_key_agreement(&self) -> Result<cose::CoseKey> {
        let send_payload =
            client_pin_command::create_payload(PinCmd::GetKeyAgreement, self.pin_protocol_version)?;
        let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;
        let authenticator_key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;
        Ok(authenticator_key_agreement)
    }

    pub fn create_pin_auth(&self, pin: &str, client_data_hash: &[u8]) -> Result<Vec<u8>> {
        let pin_token = self.get_pin_token(pin)?;

        compute_pin_uv_auth_param(&pin_token.key, client_data_hash, self.pin_protocol_version)
    }

    pub fn get_pin_token(&self, pin: &str) -> Result<PinToken> {
        if pin.is_empty() {
            return Err(anyhow!("pin not set"));
        }

        let authenticator_key_agreement = self.get_authenticator_key_agreement()?;
        let shared_secret =
            PinUvAuthSharedSecret::new(self.pin_protocol_version, &authenticator_key_agreement)?;

        // Get pinHashEnc
        let pin_hash_enc = shared_secret.encrypt_pin(pin)?;

        let send_payload = client_pin_command::create_payload_get_pin_token(
            shared_secret.public_key(),
            &pin_hash_enc,
            self.pin_protocol_version,
        )?;

        let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;

        // get pin_token (enc)
        let pin_token_enc =
            client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;

        // pintoken -> dec(pintoken)
        shared_secret.decrypt_token(&pin_token_enc)
    }

    pub fn get_pinuv_auth_token_with_permission(
        &self,
        pin: &str,
        permission: Permission,
    ) -> Result<PinToken> {
        if pin.is_empty() {
            return Err(anyhow!("pin not set"));
        }

        let authenticator_key_agreement = self.get_authenticator_key_agreement()?;
        let shared_secret =
            PinUvAuthSharedSecret::new(self.pin_protocol_version, &authenticator_key_agreement)?;

        // Get pinHashEnc
        let pin_hash_enc = shared_secret.encrypt_pin(pin)?;

        // Get pin token
        let send_payload =
            client_pin_command::create_payload_get_pin_uv_auth_token_using_pin_with_permissions(
                shared_secret.public_key(),
                &pin_hash_enc,
                permission,
                self.pin_protocol_version,
            )?;
        let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;

        // get pin_token (enc)
        let pin_token_enc =
            client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;

        // pintoken -> dec(pintoken)
        shared_secret.decrypt_token(&pin_token_enc)
    }

    pub fn set_new_pin_cmd(&self, pin: &str) -> Result<()> {
        if pin.is_empty() {
            return Err(anyhow!("new pin not set"));
        }

        // get key_agreement
        let send_payload =
            client_pin_command::create_payload(PinCmd::GetKeyAgreement, self.pin_protocol_version)?;
        let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;

        let key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

        let shared_secret = PinUvAuthSharedSecret::new(self.pin_protocol_version, &key_agreement)?;

        // newPinEnc: encrypt(shared secret, paddedPin)
        let new_pin_enc = shared_secret.encrypt(&padding_pin_64(pin)?)?;

        // pinUvAuthParam: authenticate(shared secret, newPinEnc)
        let pin_auth = shared_secret.authenticate(&new_pin_enc)?;

        // set new pin
        let send_payload = client_pin_command::create_payload_set_pin(
            shared_secret.public_key(),
            &pin_auth,
            &new_pin_enc,
            self.pin_protocol_version,
        )?;

        ctaphid::ctaphid_cbor(self, &send_payload)?;

        Ok(())
    }

    pub fn change_pin_cmd(&self, current_pin: &str, new_pin: &str) -> Result<()> {
        if current_pin.is_empty() {
            return Err(anyhow!("current pin not set"));
        }
        if new_pin.is_empty() {
            return Err(anyhow!("new pin not set"));
        }

        // get key_agreement
        let send_payload =
            client_pin_command::create_payload(PinCmd::GetKeyAgreement, self.pin_protocol_version)?;
        let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;

        let key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

        let shared_secret = PinUvAuthSharedSecret::new(self.pin_protocol_version, &key_agreement)?;

        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#changingExistingPin
        // 6.5.5.6. Changing existing PIN

        // pinHashEnc: encrypt(shared secret, LEFT(SHA-256(curPin), 16))
        let current_pin_hash_enc = shared_secret.encrypt_pin(current_pin)?;

        // newPinEnc: encrypt(shared secret, paddedPin)
        let new_pin_enc = shared_secret.encrypt(&padding_pin_64(new_pin)?)?;

        // pinUvAuthParam: authenticate(shared secret, newPinEnc || pinHashEnc)
        let mut message = new_pin_enc.clone();
        message.extend_from_slice(&current_pin_hash_enc);
        let pin_auth = shared_secret.authenticate(&message)?;

        let send_payload = client_pin_command::create_payload_change_pin(
            shared_secret.public_key(),
            &pin_auth,
            &new_pin_enc,
            &current_pin_hash_enc,
            self.pin_protocol_version,
        )?;

        ctaphid::ctaphid_cbor(self, &send_payload)?;

        Ok(())
    }
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
