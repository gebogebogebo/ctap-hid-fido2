use crate::ctaphid;
use crate::fidokey::pin::{
    create_payload, parse_cbor_client_pin_get_keyagreement, SubCommand as PinCmd,
};
use crate::pin_uv_auth_protocol::PinUvAuthSharedSecret;
use crate::FidoKeyHid;
use anyhow::Result;

#[derive(Debug, Default, Clone)]
pub struct HmacExt {
    pub shared_secret: PinUvAuthSharedSecret,
    pub salt_enc: Vec<u8>,
    pub salt_auth: Vec<u8>,
    pub pin_protocol_version: u8,
}

impl HmacExt {
    pub fn create(
        &mut self,
        device: &FidoKeyHid,
        salt1: &[u8; 32],
        salt2: Option<&[u8; 32]>,
    ) -> Result<()> {
        let send_payload = create_payload(PinCmd::GetKeyAgreement, device.pin_protocol_version)?;
        let response_cbor = ctaphid::ctaphid_cbor(device, &send_payload)?;

        let key_agreement = parse_cbor_client_pin_get_keyagreement(&response_cbor)?;

        let shared_secret =
            PinUvAuthSharedSecret::new(device.pin_protocol_version, &key_agreement)?;

        let mut salt = salt1.to_vec();
        if let Some(s) = salt2 {
            // println!("second salt");
            salt.extend_from_slice(s);
        }

        // saltEnc
        //  Encryption of the one or two salts (called salt1 (32 bytes)
        //  and salt2 (32 bytes)) using the shared secret as follows
        // One salt case: encrypt(shared secret, salt1)
        // Two salt case: encrypt(shared secret, salt1 || salt2)
        //  encrypt(key, demPlaintext) → ciphertext
        //      Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext.
        //      The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
        self.salt_enc = shared_secret.encrypt(&salt)?;
        //println!("{}", StrBuf::bufh("salt_enc", &self.salt_enc));

        // saltAuth: authenticate(shared secret, saltEnc)
        self.salt_auth = shared_secret.authenticate(&self.salt_enc)?;
        //println!("{}", StrBuf::bufh("salt_auth", &self.salt_auth));

        self.pin_protocol_version = shared_secret.pin_protocol_version();
        self.shared_secret = shared_secret;

        Ok(())
    }
}
