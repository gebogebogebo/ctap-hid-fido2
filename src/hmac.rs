use crate::ctaphid;
use crate::enc_aes256_cbc;
use crate::enc_hmac_sha_256;
use crate::ss::SharedSecret;
use crate::FidoKeyHid;
use anyhow::{Error, Result};

use crate::fidokey::pin::{
    create_payload,
    SubCommand as PinCmd,
    parse_cbor_client_pin_get_keyagreement,
};

#[derive(Debug, Default, Clone)]
pub struct HmacExt {
    pub shared_secret: SharedSecret,
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
        //println!("----------");
        //println!("{}", StrBuf::bufh("salt1", salt1));

        let send_payload = create_payload(PinCmd::GetKeyAgreement).map_err(Error::msg)?;
        let response_cbor =
            ctaphid::ctaphid_cbor(device, cid, &send_payload).map_err(Error::msg)?;

        let key_agreement = parse_cbor_client_pin_get_keyagreement(&response_cbor)
                .map_err(Error::msg)?;

        //println!("key_agreement");
        //println!("{}", self.key_agreement);

        self.shared_secret = SharedSecret::new(&key_agreement).map_err(Error::msg)?;

        // saltEnc
        //  Encryption of the one or two salts (called salt1 (32 bytes)
        //  and salt2 (32 bytes)) using the shared secret as follows
        // One salt case: encrypt(shared secret, salt1)
        // Two salt case: encrypt(shared secret, salt1 || salt2)
        //  encrypt(key, demPlaintext) → ciphertext
        //      Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext.
        //      The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
        self.salt_enc = enc_aes256_cbc::encrypt_message(&self.shared_secret.secret, salt1);
        //println!("{}", StrBuf::bufh("salt_enc", &self.salt_enc));

        // saltAuth
        let sig = enc_hmac_sha_256::authenticate(&self.shared_secret.secret, &self.salt_enc);
        self.salt_auth = sig[0..16].to_vec();
        //println!("{}", StrBuf::bufh("salt_auth", &self.salt_auth));

        Ok(())
    }
}
