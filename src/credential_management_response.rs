use crate::util;
use serde_cbor::Value;
use crate::credential_management_params;

// PEND Utilに移動する
fn cbor_get_string_from_map(cbor_map: &Value,get_key: &str)-> Option<String>{
    if let Value::Map(xs) = cbor_map {
        for (key, val) in xs {
            if let Value::Text(s) = key {
                if s.as_str() == get_key {
                    if let Value::Text(s) = val {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }
    None
}

// PEND Utilに移動する
fn cbor_get_bytes_from_map(cbor_map: &Value,get_key: &str)-> Option<Vec<u8>>{
    if let Value::Map(xs) = cbor_map {
        for (key, val) in xs {
            if let Value::Text(s) = key {
                if s.as_str() == get_key {
                    return util::cbor_value_to_vec_u8(val);
                }
            }
        }
    }
    None
}

fn parse_cbor_public_key_credential_rp_entity(obj: &Value) -> credential_management_params::PublicKeyCredentialRpEntity {
    let mut rp = credential_management_params::PublicKeyCredentialRpEntity::default();
    rp.id = cbor_get_string_from_map(obj,"id").unwrap_or_default();
    rp.name = cbor_get_string_from_map(obj,"name").unwrap_or_default();
    rp
}

fn parse_cbor_public_key_credential_user_entity(obj: &Value) -> credential_management_params::PublicKeyCredentialUserEntity {
    let mut user = credential_management_params::PublicKeyCredentialUserEntity::default();
    user.id = cbor_get_bytes_from_map(obj,"id").unwrap_or_default();
    user.name = cbor_get_string_from_map(obj,"name").unwrap_or_default();
    user.display_name = cbor_get_string_from_map(obj,"displayName").unwrap_or_default();
    user
}

fn parse_cbor_public_key_credential_descriptor(obj: &Value) -> credential_management_params::PublicKeyCredentialDescriptor {
    let mut credential = credential_management_params::PublicKeyCredentialDescriptor::default();
    credential.credential_id = cbor_get_bytes_from_map(obj,"id").unwrap_or_default();
    credential.credential_type = cbor_get_string_from_map(obj,"type").unwrap_or_default();
    credential
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
                    0x03 => data.public_key_credential_rp_entity = parse_cbor_public_key_credential_rp_entity(val),
                    0x04 => data.rpid_hash = util::cbor_value_to_vec_u8(val).unwrap(),
                    0x05 => data.total_rps = util::cbor_cast_value(val).unwrap(),
                    0x06 => data.public_key_credential_user_entity = parse_cbor_public_key_credential_user_entity(val),
                    0x07 => data.public_key_credential_descriptor = parse_cbor_public_key_credential_descriptor(val),
                    // 0x08 => PEND
                    0x09 => data.total_credentials = util::cbor_cast_value(val).unwrap(),
                    _ => println!("parse_cbor_member - unknown info {:?}", member),
                }
            }
        }
        Ok(data)
    } else {
        Err(String::from("parse error!"))
    }
}
