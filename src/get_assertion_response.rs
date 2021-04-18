use crate::get_assertion_params;
use crate::util;
use byteorder::{BigEndian, ReadBytesExt};
use serde_cbor::Value;
use std::io::Cursor;
use crate::credential_management_params;

fn parse_cbor_authdata(authdata: Vec<u8>, ass: &mut get_assertion_params::Assertion) {
    // copy
    ass.auth_data = authdata.to_vec();

    let mut index = 0;

    let clo_vec = |idx: usize, x: usize| (authdata[idx..idx + x].to_vec(), idx + x);

    // rpIdHash	(32)
    let ret = clo_vec(index, 32);
    ass.rpid_hash = ret.0;
    index = ret.1;

    // flags(1)
    let byte = authdata[index];
    ass.flags_user_present_result = if let 0x01 = byte & 0x01 { true } else { false };
    ass.flags_user_verified_result = if let 0x04 = byte & 0x04 { true } else { false };
    ass.flags_attested_credential_data_included = if let 0x40 = byte & 0x40 { true } else { false };
    ass.flags_extension_data_included = if let 0x80 = byte & 0x80 { true } else { false };
    index = index + 1;

    // signCount(4)
    let clo = |idx: usize, x: usize| {
        let mut rdr = Cursor::new(authdata[idx..idx + x].to_vec());
        (rdr.read_u32::<BigEndian>().unwrap(), idx + x)
    };
    let ret = clo(index, 4);
    ass.sign_count = ret.0;
    //index = ret.1;
}

fn parse_cbor_public_key_credential_user_entity(
    obj: &Value,
    ass: &mut get_assertion_params::Assertion,
) {
    ass.user = 
    credential_management_params::PublicKeyCredentialUserEntity::default()
    .get_id(obj)
    .get_name(obj)
    .get_display_name(obj);

    //ass.user_id = util::cbor_get_bytes_from_map(obj,"id").unwrap();
    //ass.user_name = util::cbor_get_string_from_map(obj,"name").unwrap();
    //ass.user_display_name = util::cbor_get_string_from_map(obj,"displayName").unwrap();
}

fn parse_cbor_member(
    member: i128,
    val: &Value,
    ass: &mut get_assertion_params::Assertion,
) -> Result<(), String> {
    match member {
        0x01 => ass.credential_id = util::cbor_get_bytes_from_map(val,"id")?,
        0x02 => {
            if let Value::Bytes(xs) = val {
                parse_cbor_authdata(xs.to_vec(), ass);
            }
        }
        0x03 => ass.signature = util::cbor_value_to_vec_u8(val)?,
        0x04 => parse_cbor_public_key_credential_user_entity(val, ass),
        0x05 => ass.number_of_credentials = util::cbor_value_to_num(val)?,
        _ => println!("- anything error"),
    }
    Ok(())
}

pub fn parse_cbor(bytes: &[u8]) -> Result<get_assertion_params::Assertion, String> {
    let mut ass = get_assertion_params::Assertion::default();
    let maps = util::cbor_bytes_to_map(bytes)?;
    for (key, val) in &maps {
        if let Value::Integer(member) = key {
            parse_cbor_member(*member, val, &mut ass)?;
        }
    }
    Ok(ass)
}
