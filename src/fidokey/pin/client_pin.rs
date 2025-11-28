use super::client_pin_command;
use super::client_pin_command::Permission;
use super::client_pin_command::SubCommand as PinCmd;
use super::client_pin_response;
use super::FidoKeyHid;
use crate::ctaphid;
use crate::encrypt::cose;
use crate::encrypt::enc_aes256_cbc;
use crate::encrypt::enc_hmac_sha_256;
use crate::encrypt::shared_secret::SharedSecret;
use crate::encrypt::shared_secret2::SharedSecret2;
use crate::pintoken::PinToken;
use anyhow::{anyhow, Result};
use ring::rand;
use ring::rand::SecureRandom;

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

        //
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinProto2
        //
        // 6.5.7. PIN/UV Auth Protocol Two
        // [authenticate(key, message) → signature]
        //

        // 1. If key is longer than 32 bytes, discard the excess. (This selects the HMAC-key portion of the shared secret. When key is the pinUvAuthToken, it is exactly 32 bytes long and thus this step has no effect.)
        // skip

        // 2. Return the result of computing HMAC-SHA-256 on key and message.
        let sig = enc_hmac_sha_256::authenticate(&pin_token.key, client_data_hash);
        Ok(sig[0..16].to_vec())
    }

    pub fn get_pin_token(&self, pin: &str) -> Result<PinToken> {
        if !pin.is_empty() {
            let authenticator_key_agreement = self.get_authenticator_key_agreement()?;

            if self.pin_protocol_version == 1 {
                let shared_secret = SharedSecret::new(&authenticator_key_agreement)?;
                let pin_hash_enc = shared_secret.encrypt_pin(pin)?;

                let send_payload = client_pin_command::create_payload_get_pin_token(
                    &shared_secret.public_key,
                    &pin_hash_enc,
                    self.pin_protocol_version,
                )?;

                let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;

                // get pin_token (enc)
                let mut pin_token_enc =
                    client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;

                // pintoken -> dec(pintoken)
                let pin_token_dec = shared_secret.decrypt_token(&mut pin_token_enc)?;

                Ok(pin_token_dec)
            } else if self.pin_protocol_version == 2 {
                let shared_secret = SharedSecret2::new(&authenticator_key_agreement)?;
                let pin_hash_enc = shared_secret.encrypt_pin(pin)?;

                let send_payload = client_pin_command::create_payload_get_pin_token(
                    &shared_secret.public_key,
                    &pin_hash_enc,
                    self.pin_protocol_version,
                )?;

                let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;

                // get pin_token (enc)
                let pin_token_enc =
                    client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;

                // pintoken -> dec(pintoken)
                let pin_token_dec = shared_secret.decrypt_token(&pin_token_enc)?;

                Ok(pin_token_dec)
            } else {
                Err(anyhow!("unknown pin_protocol_version"))
            }
        } else {
            Err(anyhow!("pin not set"))
        }
    }

    pub fn get_pinuv_auth_token_with_permission(
        &self,
        pin: &str,
        permission: Permission,
    ) -> Result<PinToken> {
        if !pin.is_empty() {
            let authenticator_key_agreement = self.get_authenticator_key_agreement()?;

            if self.pin_protocol_version == 1 {
                // Get pinHashEnc
                // - shared_secret.public_key -> platform KeyAgreement
                let shared_secret = SharedSecret::new(&authenticator_key_agreement)?;
                let pin_hash_enc = shared_secret.encrypt_pin(pin)?;

                // Get pin token
                let send_payload =
                    client_pin_command::create_payload_get_pin_uv_auth_token_using_pin_with_permissions(
                        &shared_secret.public_key,
                        &pin_hash_enc,
                        permission,
                        self.pin_protocol_version,
                    )?;
                let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;

                // get pin_token (enc)
                let mut pin_token_enc =
                    client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;

                // pintoken -> dec(pintoken)
                let pin_token_dec = shared_secret.decrypt_token(&mut pin_token_enc)?;

                Ok(pin_token_dec)
            } else if self.pin_protocol_version == 2 {
                // Get pinHashEnc
                // - shared_secret.public_key -> platform KeyAgreement
                let shared_secret = SharedSecret2::new(&authenticator_key_agreement)?;
                let pin_hash_enc = shared_secret.encrypt_pin(pin)?;

                // Get pin token
                let send_payload =
                    client_pin_command::create_payload_get_pin_uv_auth_token_using_pin_with_permissions(
                        &shared_secret.public_key,
                        &pin_hash_enc,
                        permission,
                        self.pin_protocol_version,
                    )?;
                let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;

                // get pin_token (enc)
                let pin_token_enc =
                    client_pin_response::parse_cbor_client_pin_get_pin_token(&response_cbor)?;

                // pintoken -> dec(pintoken)
                let pin_token_dec = shared_secret.decrypt_token(&pin_token_enc)?;

                Ok(pin_token_dec)
            } else {
                Err(anyhow!("unknown pin_protocol_version"))
            }
        } else {
            Err(anyhow!("pin not set"))
        }
    }

    pub fn set_pin(&self, pin: &str) -> Result<()> {
        if pin.is_empty() {
            return Err(anyhow!("new pin not set"));
        }

        // get key_agreement
        let send_payload =
            client_pin_command::create_payload(PinCmd::GetKeyAgreement, self.pin_protocol_version)?;
        let response_cbor = ctaphid::ctaphid_cbor(self, &send_payload)?;

        let key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

        // get public_key, pin_auth, new_pin_enc
        let (public_key, pin_auth, new_pin_enc) = if self.pin_protocol_version == 1 {
            let shared_secret = SharedSecret::new(&key_agreement)?;

            let new_pin_enc = create_new_pin_enc(&shared_secret, pin)?;

            let pin_auth = create_pin_auth_for_set_pin(&shared_secret, &new_pin_enc)?;
            
            (shared_secret.public_key, pin_auth, new_pin_enc)
        } else if self.pin_protocol_version == 2 {
            let shared_secret = SharedSecret2::new(&key_agreement)?;

            let new_pin_enc = create_new_pin_enc2(&shared_secret, pin)?;

            let pin_auth = create_pin_auth_for_set_pin2(&shared_secret, &new_pin_enc)?;

            (shared_secret.public_key, pin_auth, new_pin_enc)
        } else {
            return Err(anyhow!("unknown pin_protocol_version"))
        };

        // set new pin
        let send_payload = client_pin_command::create_payload_set_pin(
            &public_key,
            &pin_auth,
            &new_pin_enc,
            self.pin_protocol_version,
        )?;

        ctaphid::ctaphid_cbor(self, &send_payload)?;

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

fn create_pin_auth_for_set_pin2(
    shared_secret: &SharedSecret2,
    new_pin_enc: &[u8],
) -> Result<Vec<u8>> {
    // HMAC-SHA-256(sharedSecret, message)
    // If key is longer than 32 bytes, discard the excess. (This selects the HMAC-key portion of the shared secret. When key is the pinUvAuthToken, it is exactly 32 bytes long and thus this step has no effect.)
    let key = shared_secret.secret[0..32].to_vec();
    let sig = enc_hmac_sha_256::authenticate(&key, new_pin_enc);

    // Return the result of computing HMAC-SHA-256 on key and message.
    // 32byte
    let pin_auth = sig.to_vec();

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

fn create_pin_auth_for_change_pin2(
    shared_secret: &SharedSecret2,
    new_pin_enc: &[u8],
    current_pin_hash_enc: &[u8],
) -> Result<Vec<u8>> {
    // source data
    let mut message = vec![];
    message.append(&mut new_pin_enc.to_vec());
    message.append(&mut current_pin_hash_enc.to_vec());

    // HMAC-SHA-256(sharedSecret, message)
    // If key is longer than 32 bytes, discard the excess. (This selects the HMAC-key portion of the shared secret. When key is the pinUvAuthToken, it is exactly 32 bytes long and thus this step has no effect.)
    let key = shared_secret.secret[0..32].to_vec();
    let sig = enc_hmac_sha_256::authenticate(&key, &message);

    // Return the result of computing HMAC-SHA-256 on key and message.
    // 32byte
    let pin_auth = sig.to_vec();

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
fn create_new_pin_enc2(shared_secret: &SharedSecret2, new_pin: &str) -> Result<Vec<u8>> {
    let new_pin_64 = padding_pin_64(new_pin)?;

    let aes_key: &[u8; 32] = shared_secret.secret[32..].try_into()?;

    // Let iv be a 16-byte, random bytestring.
    let mut iv = [0u8; 16];
    let rng = rand::SystemRandom::new();
    rng.fill(&mut iv)
        .map_err(|_| anyhow!("Failed to generate random IV"))?;

    let ciphertext = enc_aes256_cbc::encrypt_message_with_iv(aes_key, &iv, &new_pin_64);

    // Return iv || ct.
    // Concatenate iv and ct(ciphertext)
    let mut new_pin_enc = vec![];
    new_pin_enc.extend_from_slice(&iv);
    new_pin_enc.extend_from_slice(&ciphertext);

    Ok(new_pin_enc)
}

// TODO この device は self でいいのでは
pub fn change_pin(device: &FidoKeyHid, current_pin: &str, new_pin: &str) -> Result<()> {
    if current_pin.is_empty() {
        return Err(anyhow!("current pin not set"));
    }
    if new_pin.is_empty() {
        return Err(anyhow!("new pin not set"));
    }

    // get key_agreement
    let send_payload =
        client_pin_command::create_payload(PinCmd::GetKeyAgreement, device.pin_protocol_version)?;
    let response_cbor = ctaphid::ctaphid_cbor(device, &send_payload)?;

    let key_agreement =
        client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

    // get public_key, pin_auth, new_pin_enc, current_pin_hash_enc
    let (public_key, pin_auth, new_pin_enc, current_pin_hash_enc) = if device.pin_protocol_version == 1 {
        let shared_secret = SharedSecret::new(&key_agreement)?;

        let current_pin_hash_enc = shared_secret.encrypt_pin(current_pin)?;

        let new_pin_enc = create_new_pin_enc(&shared_secret, new_pin)?;

        let pin_auth =
            create_pin_auth_for_change_pin(&shared_secret, &new_pin_enc, &current_pin_hash_enc)?;

        (shared_secret.public_key, pin_auth, new_pin_enc, current_pin_hash_enc.into())
    } else if device.pin_protocol_version == 2 {
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#changingExistingPin
        // 6.5.5.6. Changing existing PIN

        let shared_secret = SharedSecret2::new(&key_agreement)?;

        // 4. pinHashEnc: The result of calling encrypt(shared secret, LEFT(SHA-256(curPin), 16)).
        let current_pin_hash_enc = shared_secret.encrypt_pin(current_pin)?;

        // 5. newPinEnc: the result of calling encrypt(shared secret, paddedPin) where paddedPin is newPin padded on the right with 0x00 bytes to make it 64 bytes long. (Since the maximum length of newPin is 63 bytes, there is always at least one byte of padding.)
        let new_pin_enc = create_new_pin_enc2(&shared_secret, new_pin)?;

        // 6. pinUvAuthParam: the result of calling authenticate(shared secret, newPinEnc || pinHashEnc).
        let pin_auth =
            create_pin_auth_for_change_pin2(&shared_secret, &new_pin_enc, &current_pin_hash_enc)?;

        (shared_secret.public_key, pin_auth, new_pin_enc, current_pin_hash_enc)
    } else {
        return Err(anyhow!("unknown pin_protocol_version"))
    };

    let send_payload = client_pin_command::create_payload_change_pin(
        &public_key,
        &pin_auth,
        &new_pin_enc,
        &current_pin_hash_enc,
        device.pin_protocol_version,
    )?;

    ctaphid::ctaphid_cbor(device, &send_payload)?;

    Ok(())
}
