use anyhow::{Result};
use serde_cbor::Value;
use super::credential_management_params;
use crate::public_key::PublicKey;
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use crate::public_key_credential_rp_entity::PublicKeyCredentialRpEntity;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::util;

pub(crate) fn parse_cbor(
    bytes: &[u8],
) -> Result<credential_management_params::CredentialManagementData> {
    let mut data = credential_management_params::CredentialManagementData::default();
    let maps = util::cbor_bytes_to_map(bytes)?;
    for (key, val) in &maps {
        if let Value::Integer(member) = key {
            match member {
                0x01 => data.existing_resident_credentials_count = util::cbor_value_to_num(val)?,
                0x02 => {
                    data.max_possible_remaining_resident_credentials_count =
                        util::cbor_value_to_num(val)?
                }
                0x03 => {
                    data.public_key_credential_rp_entity = PublicKeyCredentialRpEntity::default()
                        .get_id(val)
                        .get_name(val)
                }
                0x04 => data.rpid_hash = util::cbor_value_to_vec_u8(val)?,
                0x05 => data.total_rps = util::cbor_value_to_num(val)?,
                0x06 => {
                    data.public_key_credential_user_entity =
                        PublicKeyCredentialUserEntity::default()
                            .get_id(val)
                            .get_name(val)
                            .get_display_name(val)
                }
                0x07 => {
                    data.public_key_credential_descriptor = PublicKeyCredentialDescriptor::default()
                        .get_id(val)
                        .get_type(val)
                }
                0x08 => data.public_key = PublicKey::new(val),
                0x09 => data.total_credentials = util::cbor_value_to_num(val)?,
                0x0A => data.cred_protect = util::cbor_value_to_num(val)?,
                0x0B => data.large_blob_key = util::cbor_value_to_vec_u8(val)?,
                _ => println!("parse_cbor_member - unknown member {:?}", member),
            }
        }
    }
    Ok(data)
}
