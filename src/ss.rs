use cose::CoseKey;
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
    pub secret: [u8; 32],
}

impl SharedSecret {
    pub fn new(peer_key: &CoseKey) -> Result<Self, String> {
        let rng = rand::SystemRandom::new();
        let private =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();

        let public = &mut [0u8; agreement::PUBLIC_KEY_MAX_LEN][..private.public_key_len()];
        private.compute_public_key(public).unwrap();

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

        let mut res = SharedSecret {
            public_key: p256::P256Key::from_bytes(&public).unwrap().to_cose(),
            secret: [0; 32],
        };
        res.secret.copy_from_slice(shared_secret.as_ref());
        Ok(res)
    }

    pub fn encrypt_pin(&self, pin: &str) -> Result<[u8; 16], String> {
        self.encrypt(pin.as_bytes())
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<[u8; 16], String> {
        let hash = digest::digest(&digest::SHA256, &data);
        let message = &hash.as_ref()[0..16];
        let enc = enc_aes256_cbc::encrypt_message(&self.secret, message);
        let mut out_bytes = [0; 16];
        out_bytes.copy_from_slice(&enc[0..16]);
        Ok(out_bytes)
    }

    pub fn decrypt_token(&self, data: &mut [u8]) -> Result<PinToken, String> {
        let dec = enc_aes256_cbc::decrypt_message(&self.secret, data);
        let pin_token = PinToken::new(&dec);
        Ok(pin_token)
    }
}
