use crate::ctaphid;
use crate::encrypt::enc_aes256_cbc;
use crate::encrypt::enc_hmac_sha_256;
use crate::encrypt::shared_secret::SharedSecret;
use crate::fidokey::pin::{
    create_payload, parse_cbor_client_pin_get_keyagreement, SubCommand as PinCmd,
};
use crate::FidoKeyHid;
#[cfg(feature = "tokio")]use crate::FidoKeyHidAsync;
use anyhow::Result;

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
        salt1: &[u8; 32],
        _salt2: Option<&[u8; 32]>,
    ) -> Result<()> {
        //println!("----------");
        //println!("{}", StrBuf::bufh("salt1", salt1));

        let send_payload = create_payload(PinCmd::GetKeyAgreement)?;
        let response_cbor = ctaphid::ctaphid_cbor(device, &send_payload)?;

        let key_agreement = parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

        //println!("key_agreement");
        //println!("{}", self.key_agreement);

        self.shared_secret = SharedSecret::new(&key_agreement)?;

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

    #[cfg(feature = "tokio")]pub async fn create_async(
        &mut self,
        device: &FidoKeyHidAsync,
        salt1: &[u8; 32],
        _salt2: Option<&[u8; 32]>,
    ) -> Result<()> {
        //println!("----------");
        //println!("{}", StrBuf::bufh("salt1", salt1));

        let send_payload = create_payload(PinCmd::GetKeyAgreement)?;
        let response_cbor = ctaphid::ctaphid_cbor_async(device, &send_payload).await?;

        let key_agreement = parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

        //println!("key_agreement");
        //println!("{}", self.key_agreement);

        self.shared_secret = SharedSecret::new(&key_agreement)?;

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