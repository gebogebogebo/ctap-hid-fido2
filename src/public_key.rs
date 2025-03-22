use crate::encrypt::cose::CoseKey;
use crate::util;
use crate::util_ciborium;
use anyhow::Result;
use serde_cbor::Value;
use std::fmt;

#[derive(Debug, Default, Clone)]
pub enum PublicKeyType {
    #[default]
    Unknown = 0,
    Ecdsa256 = 1,
    Ed25519 = 2,
}

#[derive(Debug, Default, Clone)]
pub struct PublicKey {
    pub key_type: PublicKeyType,
    pub pem: String,
    pub der: Vec<u8>,
}
impl PublicKey {
    pub fn new(cbor: &Value) -> Result<Self> {
        let ciborium_value = util_ciborium::serde_to_ciborium(cbor.clone())?;
        let cose_key = CoseKey::new(&ciborium_value)?;

        let mut public_key = PublicKey::default();

        public_key.key_type = if cose_key.key_type == 1 {
            PublicKeyType::Ed25519
        } else if cose_key.key_type == 2 {
            PublicKeyType::Ecdsa256
        } else {
            PublicKeyType::Unknown
        };
        public_key.der = cose_key.to_public_key_der();
        public_key.pem = util::convert_to_publickey_pem(&public_key.der);
        Ok(public_key)
    }

    pub fn with_der(der: &[u8], public_key_type: PublicKeyType) -> Self {
        PublicKey {
            key_type: public_key_type,
            der: der.to_vec(),
            ..Default::default()
        }
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(der : {} , pem : {})",
            util::to_hex_str(&self.der),
            self.pem
        )
    }
}
