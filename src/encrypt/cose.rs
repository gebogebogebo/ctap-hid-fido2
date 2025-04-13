use crate::str_buf::StrBuf;
use crate::util_ciborium::{self, ToValue};
use anyhow::{anyhow, Result};
use ciborium::value::Value;
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Default, Clone)]
pub struct CoseKey {
    pub key_type: u16,
    pub algorithm: i32,
    pub parameters: HashMap<i16, Value>,
}

impl fmt::Display for CoseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut strbuf = StrBuf::new(12);
        strbuf
            .append("- key_type", &self.key_type)
            .append("- algorithm", &self.algorithm);
        if let Some(Value::Integer(intval)) = self.parameters.get(&-1) {
            let i32_value: i32 = i32::try_from(*intval).expect("Integer Conversion failed");
            strbuf.append("- crv", &i32_value);
        }
        if let Some(Value::Bytes(bytes)) = self.parameters.get(&-2) { 
            strbuf.appenh("- x", bytes);
        }
        if let Some(Value::Bytes(bytes)) = self.parameters.get(&-3) {
            strbuf.appenh("- y", bytes);
        }
        write!(f, "{}", strbuf.build())
    }
}

// https://tex2e.github.io/rfc-translater/html/rfc8152.html
impl CoseKey {
    pub fn new(cbor: &Value) -> Result<Self> {
        let mut cose = CoseKey::default();

        if util_ciborium::is_map(cbor) {
            let map = util_ciborium::extract_map_ref(cbor)?;
            
            for (key, val) in map {
                if util_ciborium::is_integer(key) {
                    match util_ciborium::integer_to_i64(key)? {
                        1 => {
                            // Table 21: Key Type Values
                            // 1: kty
                            //      1: OKP (Octet Key Pair) → need x
                            //      2: EC2 (Double Coordinate Curves) → need x&y
                            cose.key_type = util_ciborium::cbor_value_to_num(val)?;
                        }
                        // 2: kid
                        3 => {
                            // 3: alg
                            //       -7: ES256
                            //       -8: EdDSA
                            //      -25: ECDH-ES + HKDF-256
                            //      -35: ES384
                            //      -36: ES512
                            cose.algorithm = util_ciborium::cbor_value_to_num(val)?;
                        }
                        // 4: key_ops
                        // 5: Base IV
                        -1 => {
                            // Table 22: Elliptic Curves
                            // -1: Curves
                            //      1: P-256(EC2)
                            //      6: Ed25519(OKP)
                            let int_val: i64 = util_ciborium::cbor_value_to_num(val)?;
                            cose.parameters.insert(-1, int_val.to_value());
                        }
                        -2 => {
                            let bytes = util_ciborium::cbor_value_to_vec_u8(val)?;
                            cose.parameters.insert(-2, bytes.to_value());
                        }
                        -3 => {
                            let bytes = util_ciborium::cbor_value_to_vec_u8(val)?;
                            cose.parameters.insert(-3, bytes.to_value());
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(cose)
    }

    // TODO rename 
    pub fn to_value_cib(&self) -> Result<Value> {
        let map = vec![
            (1.to_value() , self.key_type.to_value()),
            (3.to_value() , self.algorithm.to_value()),
            (
                (-1).to_value(),
                self.parameters.get(&-1).ok_or(anyhow!("err"))?.clone(),
            ),
            (
                (-2).to_value(),
                self.parameters.get(&-2).ok_or(anyhow!("err"))?.clone(),
            ),
            (
                (-3).to_value(),
                self.parameters.get(&-3).ok_or(anyhow!("err"))?.clone(),
            ),
        ];
        Ok(map.to_value())
    }

    pub fn to_public_key_der(&self) -> Vec<u8> {
        if self.key_type == 1 {
            // case of ED25519
            // kty == 1: OKP → need x
            let pub_key = if let Some(Value::Bytes(der)) = self.parameters.get(&-2) {
                // 32byte
                der.to_vec()
            } else {
                // ?
                vec![]
            };

            pub_key
        } else if self.key_type == 2 {
            // case of Ecdsa256
            // kty == 2: EC2 → need x&y

            // tag:0x04(OCTET STRING)
            let mut pub_key = vec![0x04];

            // 2.add X
            if let Some(Value::Bytes(bytes)) = self.parameters.get(&-2) {
                pub_key.append(&mut bytes.to_vec());
            }
            // 3.add Y
            if let Some(Value::Bytes(bytes)) = self.parameters.get(&-3) {
                pub_key.append(&mut bytes.to_vec());
            }

            pub_key
        } else {
            vec![]
        }
    }
}
