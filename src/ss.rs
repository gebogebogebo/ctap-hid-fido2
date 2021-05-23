use cose::CoseKey;
use crypto::aes;
use crypto::blockmodes::NoPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use ring::error::Unspecified;
use ring::{agreement, digest, rand};
use untrusted::Input;

use crate::cose;
use crate::p256;
use crate::pintoken::PinToken;
use crate::enc_aes256_cbc;

#[derive(Debug, Default, Clone)]
pub struct SharedSecret {
    pub public_key: CoseKey,
    pub data: [u8; 32],
}

impl SharedSecret {
    pub fn new(peer_key: &CoseKey) -> Result<Self, String> {
        let rng = rand::SystemRandom::new();
        let private =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
        //    .context(String::from("FidoErrorKind::GenerateKey"));

        let public = &mut [0u8; agreement::PUBLIC_KEY_MAX_LEN][..private.public_key_len()];
        private.compute_public_key(public).unwrap();
        //.context(FidoErrorKind::GenerateKey,)?;

        let peer = p256::P256Key::from_cose(peer_key).unwrap().bytes();

        let peer = Input::from(&peer);
        let shared_secret = agreement::agree_ephemeral(
            private,
            &agreement::ECDH_P256,
            peer,
            Unspecified,
            |material| Ok(digest::digest(&digest::SHA256, material)),
        )
        .unwrap();
        //.context(FidoErrorKind::GenerateSecret)?;

        let mut res = SharedSecret {
            public_key: p256::P256Key::from_bytes(&public).unwrap().to_cose(),
            data: [0; 32],
        };
        res.data.copy_from_slice(shared_secret.as_ref());
        Ok(res)
    }

    pub fn encrypt_pin(&self, pin: &str) -> Result<[u8; 16], String> {
        self.encrypt(pin.as_bytes())
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<[u8; 16], String> {
        let hash = digest::digest(&digest::SHA256, &data);
        let message = &hash.as_ref()[0..16];
        let enc = enc_aes256_cbc::encrypt_message(&self.data, message);
        let mut out_bytes = [0; 16];
        out_bytes.copy_from_slice(&enc[0..16]);
        Ok(out_bytes)
    }

    // TODO Refactor
    pub fn decrypt_token(&self, data: &mut [u8]) -> Result<PinToken, String> {
        let mut decryptor =
            aes::cbc_decryptor(aes::KeySize::KeySize256, &self.data, &[0u8; 16], NoPadding);
        let mut input = RefReadBuffer::new(data);
        let mut out_bytes = [0; 32];
        let mut output = RefWriteBuffer::new(&mut out_bytes);
        decryptor.decrypt(&mut input, &mut output, true).unwrap();

        let pin_token = PinToken::new(&out_bytes);
        Ok(pin_token)
    }
}
