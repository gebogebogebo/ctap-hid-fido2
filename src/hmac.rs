use crate::client_pin_command;
use crate::client_pin_command::SubCommand as PinCmd;
use crate::client_pin_response;
use crate::cose::CoseKey;
use crate::ctaphid;
use crate::pintoken;
use crate::ss;
use crate::str_buf::StrBuf;
use crate::FidoKeyHid;
use anyhow::{Error, Result};
use ring::{digest, hmac};

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
        _salt2: Option<&[u8; 32]>,
    ) -> Result<()> {
        println!("----------");
        println!("{}", StrBuf::bufh("salt1", salt1));

        let send_payload =
            client_pin_command::create_payload(PinCmd::GetKeyAgreement).map_err(Error::msg)?;
        let response_cbor =
            ctaphid::ctaphid_cbor(device, cid, &send_payload).map_err(Error::msg)?;

        let key_agreement =
            client_pin_response::parse_cbor_client_pin_get_keyagreement(&response_cbor)
                .map_err(Error::msg)?;

        //println!("key_agreement");
        //println!("{}", self.key_agreement);

        let shared_secret = ss::SharedSecret::new(&key_agreement).map_err(Error::msg)?;

        println!("shared_secret.public_key");
        println!("{}", shared_secret.public_key);
        println!(
            "{}",
            StrBuf::bufh("shared_secret.shared_secret", &shared_secret.shared_secret)
        );

        self.key_agreement = shared_secret.public_key.clone();

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
        println!("{}", StrBuf::bufh("salt_enc", &self.salt_enc));

        // saltAuth(0x03)
        //  authenticate(shared secret, saltEnc)
        //   authenticate(key, message) → signature
        let token = pintoken::PinToken {
            signing_key: hmac::SigningKey::new(&digest::SHA256, &shared_secret.shared_secret),
            key: shared_secret.shared_secret.to_vec(),
        };

        self.salt_auth = token.authenticate_v2(&self.salt_enc, 16);
        println!("{}", StrBuf::bufh("salt_auth", &self.salt_auth));

        Ok(())
    }
}
