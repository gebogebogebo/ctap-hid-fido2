use crate::str_buf::StrBuf;
use crate::util;
use anyhow::{Error, Result};
use num::NumCast;
use serde_cbor::Value;
use std::collections::{BTreeMap, HashMap};
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
            strbuf.append("- crv", &intval);
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

        if let Value::Map(xs) = cbor {
            for (key, val) in xs {
                // debug
                //util::cbor_value_print(val);

                if let Value::Integer(member) = key {
                    match member {
                        1 => {
                            // Table 21: Key Type Values
                            // 1: kty
                            //      1: OKP (Octet Key Pair) → need x
                            //      2: EC2 (Double Coordinate Curves) → need x&y
                            cose.key_type = util::cbor_value_to_num(val).map_err(Error::msg)?;
                        }
                        // 2: kid
                        3 => {
                            // 3: alg
                            //       -7: ES256
                            //       -8: EdDSA
                            //      -25: ECDH-ES + HKDF-256
                            //      -35: ES384
                            //      -36: ES512
                            cose.algorithm = util::cbor_value_to_num(val).map_err(Error::msg)?;
                        }
                        // 4: key_ops
                        // 5: Base IV
                        -1 => {
                            // Table 22: Elliptic Curves
                            // -1: Curves
                            //      1: P-256(EC2)
                            //      6: Ed25519(OKP)
                            //println!("member = {:?} , val = {:?}",member,val);
                            cose.parameters.insert(
                                NumCast::from(*member).unwrap(),
                                Value::Integer(util::cbor_value_to_num(val).map_err(Error::msg)?),
                            );
                        }
                        -2 | -3 => {
                            //println!("member = {:?} , val = {:?}",member,val);
                            cose.parameters.insert(
                                NumCast::from(*member).unwrap(),
                                Value::Bytes(util::cbor_value_to_vec_u8(val).map_err(Error::msg)?),
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(cose)
    }

    pub fn to_value(&self) -> Result<Value> {
        let mut map = BTreeMap::new();
        map.insert(Value::Integer(1), Value::Integer(self.key_type.into()));
        map.insert(Value::Integer(3), Value::Integer(self.algorithm.into()));
        map.insert(
            Value::Integer(-1),
            self.parameters.get(&-1).unwrap().clone(),
        );
        map.insert(
            Value::Integer(-2),
            self.parameters.get(&-2).unwrap().clone(),
        );
        map.insert(
            Value::Integer(-3),
            self.parameters.get(&-3).unwrap().clone(),
        );
        Ok(Value::Map(map))
    }

    pub fn to_public_key_der(&self) -> Vec<u8> {
        if self.key_type == 2 {
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
            // kty == 1: OKP → need x&y

            // TODO case of ED25519
            // ???
            vec![]
        }
    }
}
