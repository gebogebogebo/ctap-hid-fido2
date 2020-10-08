use crate::util;
use base64;
use byteorder::{BigEndian, WriteBytesExt};
use num::NumCast;
use serde_cbor::Value;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct CoseKey {
    pub key_type: u16,
    pub algorithm: i32,
    pub parameters: HashMap<i16, Value>,
}

impl CoseKey {
    #[allow(dead_code)]
    pub fn print(self: &CoseKey, title: &str) {
        println!("{}", title);
        println!("- kty       = {:?}", self.key_type);
        println!("- alg       = {:?}", self.algorithm);
        if let Some(Value::Integer(intval)) = self.parameters.get(&-1) {
            println!("- crv       = {:?}", intval);
        }
        if let Some(Value::Bytes(bytes)) = self.parameters.get(&-2) {
            println!(
                "- x({:02})     = {:?}",
                bytes.len(),
                util::to_hex_str(bytes)
            );
        }
        if let Some(Value::Bytes(bytes)) = self.parameters.get(&-3) {
            println!(
                "- y({:02})     = {:?}",
                bytes.len(),
                util::to_hex_str(bytes)
            );
        }
    }

    pub fn decode(cbor: &Value) -> Result<Self, String> {
        let mut cose = CoseKey::default();

        if let Value::Map(xs) = cbor {
            for (key, val) in xs {
                // debug
                //util::cbor_value_print(val);

                if let Value::Integer(member) = key {
                    match member {
                        1 => cose.key_type = util::cbor_cast_value(val).unwrap(),
                        3 => cose.algorithm = util::cbor_cast_value(val).unwrap(),
                        -1 => {
                            //println!("member = {:?} , val = {:?}",member,val);
                            cose.parameters.insert(
                                NumCast::from(*member).unwrap(),
                                Value::Integer(util::cbor_cast_value(val).unwrap()),
                            );
                        }
                        -2 | -3 => {
                            //println!("member = {:?} , val = {:?}",member,val);
                            cose.parameters.insert(
                                NumCast::from(*member).unwrap(),
                                Value::Bytes(util::cbor_value_to_vec_u8(val).unwrap()),
                            );
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(cose)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut wtr = vec![];

        // key type
        wtr.write_i16::<BigEndian>(0x01).unwrap();
        wtr.write_u16::<BigEndian>(self.key_type).unwrap();

        // algorithm
        wtr.write_i16::<BigEndian>(0x02).unwrap();
        wtr.write_i32::<BigEndian>(self.algorithm).unwrap();

        for (key, value) in self.parameters.iter() {
            wtr.write_i16::<BigEndian>(*key).unwrap();
            if let Value::Bytes(bytes) = value {
                wtr.append(&mut bytes.to_vec());
            }
        }

        wtr
    }

    pub fn convert_to_publickey_der(&self) -> Vec<u8> {
        let mut pub_key = vec![];

        // 1.metadata(26byte)
        let meta_header =
            hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
        pub_key.append(&mut meta_header.to_vec());

        // 2.0x04
        pub_key.push(0x04);

        // 3.add X
        if let Some(Value::Bytes(bytes)) = self.parameters.get(&-2) {
            pub_key.append(&mut bytes.to_vec());
        }
        // 4.add Y
        if let Some(Value::Bytes(bytes)) = self.parameters.get(&-3) {
            pub_key.append(&mut bytes.to_vec());
        }

        pub_key
    }

    pub fn convert_to_publickey_pem(&self) -> String {
        let public_key_der = self.convert_to_publickey_der();

        // 1.encode Base64
        let base64_str = base64::encode(public_key_der);

        // 2. /n　every 64 characters
        let pem_base = {
            let mut pem_base = "".to_string();
            let mut counter = 0;
            for c in base64_str.chars() {
                pem_base = pem_base + &c.to_string();
                if counter == 64 - 1 {
                    pem_base = pem_base + &"\n".to_string();
                    counter = 0;
                } else {
                    counter = counter + 1;
                }
            }
            pem_base + &"\n".to_string()
        };

        // 3. Header and footer
        let pem_data = "-----BEGIN PUBLIC KEY-----\n".to_string()
            + &pem_base
            + &"-----END PUBLIC KEY-----".to_string();

        /*
        println!(
            "- public_key_pem  = {:?}",pem_data
        );
        */

        pem_data
    }
}
