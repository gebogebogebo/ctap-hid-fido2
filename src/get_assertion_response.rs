use crate::get_assertion_params;
use crate::util;
use byteorder::{BigEndian, ReadBytesExt};
use serde_cbor::Value;
use std::io::Cursor;

fn parse_cbor_authdata(authdata: Vec<u8>, ass: &mut get_assertion_params::Assertion) {
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
    if let Value::Map(xs) = obj {
        for (key, val) in xs {
            if let Value::Text(s) = key {
                let ss = s.as_str();
                match ss {
                    "id" => ass.user_id = util::cbor_value_to_vec_u8(val).unwrap(),
                    "name" => {
                        if let Value::Text(s) = val {
                            ass.user_name = s.to_string();
                        }
                    }
                    "displayName" => {
                        if let Value::Text(s) = val {
                            ass.user_display_name = s.to_string();
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

fn parse_cbor_member(member: i128, val: &Value, ass: &mut get_assertion_params::Assertion) {
    //util::cbor_value_print(val);

    match member {
        1 => {
            // 0x01:credential
            if let Value::Map(xs) = val {
                for (key, val2) in xs {
                    if let Value::Text(s) = key {
                        let ss = s.as_str();
                        match ss {
                            "id" => ass.credential_id = util::cbor_value_to_vec_u8(val2).unwrap(),
                            "type" => {}
                            _ => {}
                        }
                    }
                }
            }
        }
        2 => {
            // 0x02:AuthData
            if let Value::Bytes(xs) = val {
                parse_cbor_authdata(xs.to_vec(), ass);
            }
        }
        3 => {
            // 0x03:signature
            ass.signature = util::cbor_value_to_vec_u8(val).unwrap();
        }
        4 => {
            // 0x04:user
            parse_cbor_public_key_credential_user_entity(val, ass);
        }
        5 => {
            // 0x05:numberOfCredentials
            ass.number_of_credentials = util::cbor_cast_value(val).unwrap();
        }
        _ => println!("- anything error"),
    }
}

pub fn parse_cbor(bytes: &[u8]) -> Result<get_assertion_params::Assertion, String> {
    let mut ass = get_assertion_params::Assertion::default();

    let cbor: Value = serde_cbor::from_slice(bytes).unwrap();
    if let Value::Map(map) = cbor {
        for (key, val) in &map {
            if let Value::Integer(member) = key {
                //println!("member = {}",member);
                parse_cbor_member(*member, val, &mut ass);
            }
        }
        Ok(ass)
    } else {
        Err(String::from("parse error!"))
    }
}
