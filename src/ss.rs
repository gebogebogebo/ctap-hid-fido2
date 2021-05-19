use crypto::aes;
use crypto::blockmodes::NoPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use ring::error::Unspecified;
use ring::{agreement, digest, rand};
use untrusted::Input;

use crate::cose;
use crate::p256;
use crate::pintoken::PinToken;

#[derive(Debug)]
pub struct SharedSecret {
    pub public_key: cose::CoseKey,
    pub shared_secret: [u8; 32],
}

impl SharedSecret {
    pub fn new(peer_key: &cose::CoseKey) -> Result<Self, String> {
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
            shared_secret: [0; 32],
        };
        res.shared_secret.copy_from_slice(shared_secret.as_ref());
        Ok(res)
    }

    /*
    pub fn encrypt_pin(&self, pin: &str) -> Result<[u8; 16], String> {
        let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            &self.shared_secret,
            &[0u8; 16],
            NoPadding,
        );
        let pin_bytes = pin.as_bytes();
        let hash = digest::digest(&digest::SHA256, &pin_bytes);
        let in_bytes = &hash.as_ref()[0..16];
        let mut input = RefReadBuffer::new(&in_bytes);
        let mut out_bytes = [0; 16];
        let mut output = RefWriteBuffer::new(&mut out_bytes);
        encryptor.encrypt(&mut input, &mut output, true).unwrap();
        Ok(out_bytes)
    }
    */

    pub fn encrypt_pin(&self, pin: &str) -> Result<[u8; 16], String> {
        self.encrypt(pin.as_bytes())
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<[u8; 16], String> {
        let mut encryptor = aes::cbc_encryptor(
            aes::KeySize::KeySize256,
            &self.shared_secret,
            &[0u8; 16],
            NoPadding,
        );
        let hash = digest::digest(&digest::SHA256, &data);
        let in_bytes = &hash.as_ref()[0..16];
        let mut input = RefReadBuffer::new(&in_bytes);
        let mut out_bytes = [0; 16];
        let mut output = RefWriteBuffer::new(&mut out_bytes);
        encryptor.encrypt(&mut input, &mut output, true).unwrap();
        Ok(out_bytes)
    }

    pub fn decrypt_token(&self, data: &mut [u8]) -> Result<PinToken, String> {
        let mut decryptor = aes::cbc_decryptor(
            aes::KeySize::KeySize256,
            &self.shared_secret,
            &[0u8; 16],
            NoPadding,
        );
        let mut input = RefReadBuffer::new(data);
        let mut out_bytes = [0; 32];
        let mut output = RefWriteBuffer::new(&mut out_bytes);
        decryptor.decrypt(&mut input, &mut output, true).unwrap();

        let pin_token = PinToken::new(&out_bytes);
        Ok(pin_token)
    }
}
