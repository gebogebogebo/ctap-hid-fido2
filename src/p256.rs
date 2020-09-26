use crate::cose;
use serde_cbor::Value;

#[derive(Debug, Default)]
pub struct P256Key {
    x: [u8; 32],
    y: [u8; 32],
}

impl P256Key {
    pub fn from_cose(cose: &cose::CoseKey) -> Result<Self, String> {
        if cose.key_type != 2 || (cose.algorithm != -7 && cose.algorithm != -25) {
            return Err(String::from("Err KeyType"));
        }

        if let (Some(Value::Integer(curve)), Some(Value::Bytes(x)), Some(Value::Bytes(y))) = (
            cose.parameters.get(&-1),
            cose.parameters.get(&-2),
            cose.parameters.get(&-3),
        ) {
            if *curve != 1 {
                return Err(String::from("Err KeyType"));
            }
            let mut key = P256Key::default();
            key.x.copy_from_slice(x);
            key.y.copy_from_slice(y);
            return Ok(key);
        }
        return Err(String::from("Err KeyType"));
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return Err(String::from("FidoErrorKind::CborDecode"));
        }
        let mut res = P256Key::default();
        res.x.copy_from_slice(&bytes[1..33]);
        res.y.copy_from_slice(&bytes[33..65]);
        Ok(res)
    }

    pub fn to_cose(&self) -> cose::CoseKey {
        cose::CoseKey {
            key_type: 2,
            algorithm: -7,
            parameters: [
                (-1, Value::Integer(1)),
                (-2, Value::Bytes(self.x.to_vec())),
                (-3, Value::Bytes(self.y.to_vec())),
            ]
            .iter()
            .cloned()
            .collect(),
        }
    }

    pub fn bytes(&self) -> [u8; 65] {
        let mut bytes = [0; 65];
        bytes[0] = 0x04;
        bytes[1..33].copy_from_slice(&self.x);
        bytes[33..65].copy_from_slice(&self.y);
        bytes
    }
}
