use crate::util;
use serde_cbor::Value;
use crate::credential_management_params;

fn parse_cbor_public_key_credential_rp_entity(obj: &Value) -> credential_management_params::PublicKeyCredentialRpEntity {
    let mut rp = credential_management_params::PublicKeyCredentialRpEntity::default();
    if let Value::Map(xs) = obj {
        for (key, val) in xs {
            if let Value::Text(s) = key {
                match s.as_str() {
                    "id" => if let Value::Text(s) = val {
                        rp.id = s.to_string()
                    },
                    "name" => if let Value::Text(s) = val {
                        rp.name = s.to_string()
                    },
                    _ => {}
                }
            }
        }
    }
    rp
}

pub fn parse_cbor(bytes: &[u8]) -> Result<credential_management_params::CredsMetadata, String> {
    let mut data = credential_management_params::CredsMetadata::default();

    let cbor = serde_cbor::from_slice(bytes).unwrap();
    if let Value::Map(n) = cbor {
        for (key, val) in &n {
            if let Value::Integer(member) = key {
                match member {
                    0x01 => data.existing_resident_credentials_count = util::cbor_cast_value(val).unwrap(),
                    0x02 => data.max_possible_remaining_resident_credentials_count = util::cbor_cast_value(val).unwrap(),
                    0x03 => data.rp = parse_cbor_public_key_credential_rp_entity(val),
                    0x04 => data.rpid_hash = util::cbor_value_to_vec_u8(val).unwrap(),
                    0x05 => data.total_rps = util::cbor_cast_value(val).unwrap(),
                    _ => println!("parse_cbor_member - unknown info {:?}", member),
                }
            }
        }
        Ok(data)
    } else {
        Err(String::from("parse error!"))
    }
}
