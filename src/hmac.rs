use crate::client_pin_command;
use crate::client_pin_response;
use crate::ctaphid;
use crate::pintoken;
use crate::ss;
use crate::FidoKeyHid;
use crate::client_pin_command::SubCommand as PinCmd;
use ring::{digest, hmac};
use crate::cose::CoseKey;
use anyhow::{Error, Result};

#[derive(Debug, Default)]
pub struct HmacExt {
    pub key_agreement: CoseKey,
    pub salt_enc: Vec<u8>,
    pub salt_auth: Vec<u8>,
}

impl HmacExt {
    pub fn create(
        &mut self,
        device: &FidoKeyHid,
        cid: &[u8],
        salt1: &[u8; 32],
        _salt2: Option<&[u8; 32]>
    ) -> Result<()> {

        let send_payload =
            client_pin_command::create_payload(PinCmd::GetKeyAgreement).map_err(Error::msg)?;
        let response_cbor = ctaphid::ctaphid_cbor(device, cid, &send_payload).map_err(Error::msg)?;
    
        self.key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor).map_err(Error::msg)?;
    
        let shared_secret = ss::SharedSecret::new(&self.key_agreement).map_err(Error::msg)?;
    
        // https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#sctn-hmac-secret-extension
    
        // saltEnc(0x02)
        //  Encryption of the one or two salts (called salt1 (32 bytes) 
        //  and salt2 (32 bytes)) using the shared secret as follows
        // One salt case: encrypt(shared secret, salt1)
        // Two salt case: encrypt(shared secret, salt1 || salt2)
        //  encrypt(key, demPlaintext) → ciphertext
        //      Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext. 
        //      The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
        self.salt_enc = shared_secret.encrypt2(salt1).map_err(Error::msg)?.to_vec();
    
    
        // saltAuth(0x03)
        //  authenticate(shared secret, saltEnc)
        //   authenticate(key, message) → signature
        let token = pintoken::PinToken {
            signing_key: hmac::SigningKey::new(&digest::SHA256, &self.salt_enc),
            key: self.salt_enc.to_vec(),
        };
    
        self.salt_auth = token.authenticate_v2(&self.salt_enc, 16);
    
        Ok(())
    }
}
