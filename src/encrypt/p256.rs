use crate::encrypt::cose;
use crate::util_ciborium::ToValue;
use anyhow::{anyhow, Result};
use ciborium::value::Value;

#[derive(Debug, Default)]
pub struct P256Key {
    x: [u8; 32],
    y: [u8; 32],
}

impl P256Key {
    pub fn from_cose(cose: &cose::CoseKey) -> Result<Self> {
        if cose.key_type != 2 || (cose.algorithm != -7 && cose.algorithm != -25) {
            return Err(anyhow!("Err KeyType"));
        }

        if let (Some(Value::Integer(curve)), Some(Value::Bytes(x)), Some(Value::Bytes(y))) = (
            cose.parameters.get(&-1),
            cose.parameters.get(&-2),
            cose.parameters.get(&-3),
        ) {
            if *curve != 1.into() {
                return Err(anyhow!("Err KeyType"));
            }
            let x: [u8; 32] = x
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("Err KeyType"))?;
            let y: [u8; 32] = y
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("Err KeyType"))?;
            return Ok(P256Key { x, y });
        }
        Err(anyhow!("Err KeyType"))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return Err(anyhow!("FidoErrorKind::CborDecode"));
        }
        let mut res = P256Key::default();
        res.x.copy_from_slice(&bytes[1..33]);
        res.y.copy_from_slice(&bytes[33..65]);
        Ok(res)
    }

    pub fn to_cose(&self) -> cose::CoseKey {
        cose::CoseKey {
            key_type: 2,
            algorithm: -25,
            parameters: [
                (-1, 1.to_value()),
                (-2, self.x.to_vec().to_value()),
                (-3, self.y.to_vec().to_value()),
            ]
            .into(),
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

#[cfg(test)]
mod tests {
    use super::P256Key;
    use crate::encrypt::cose::CoseKey;
    use crate::util_ciborium::ToValue;

    fn cose_key(x: Vec<u8>, y: Vec<u8>) -> CoseKey {
        CoseKey {
            key_type: 2,
            algorithm: -25,
            parameters: [(-1, 1.to_value()), (-2, x.to_value()), (-3, y.to_value())].into(),
        }
    }

    #[test]
    fn test_from_cose_valid_coordinates() {
        let key = P256Key::from_cose(&cose_key(vec![1u8; 32], vec![2u8; 32])).unwrap();
        let bytes = key.bytes();
        assert_eq!(bytes[0], 0x04);
        assert_eq!(&bytes[1..33], &[1u8; 32]);
        assert_eq!(&bytes[33..65], &[2u8; 32]);
    }

    #[test]
    fn test_from_cose_rejects_invalid_coordinate_length() {
        assert!(P256Key::from_cose(&cose_key(vec![1u8; 33], vec![2u8; 32])).is_err());
        assert!(P256Key::from_cose(&cose_key(vec![1u8; 32], vec![2u8; 31])).is_err());
        assert!(P256Key::from_cose(&cose_key(vec![], vec![])).is_err());
    }
}
