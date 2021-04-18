use crate::credential_management_params;
use crate::util;
use serde_cbor::Value;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;

pub(crate) fn parse_cbor(
    bytes: &[u8],
) -> Result<credential_management_params::CredentialManagementData, String> {
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
                    data.public_key_credential_rp_entity =
                        credential_management_params::PublicKeyCredentialRpEntity::default()
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
                    data.public_key_credential_descriptor =
                        credential_management_params::PublicKeyCredentialDescriptor::default()
                            .get_id(val)
                            .get_type(val)
                }
                0x08 => {
                    data.public_key = credential_management_params::PublicKey::default().get(val)
                }
                0x09 => data.total_credentials = util::cbor_value_to_num(val)?,
                0x0A => data.cred_protect = util::cbor_value_to_num(val)?,
                0x0B => data.large_blob_key = util::cbor_value_to_vec_u8(val)?,
                _ => println!("parse_cbor_member - unknown member {:?}", member),
            }
        }
    }
    Ok(data)
}
