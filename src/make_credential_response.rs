use crate::make_credential_params::Attestation;
use crate::util;

use byteorder::{BigEndian, ReadBytesExt};
use serde_cbor::Value;
use std::io::Cursor;

fn parse_cbor_att_stmt(obj: &Value, att: &mut Attestation)->Result<(),String> {
    if let Value::Map(xs) = obj {
        for (key, val) in xs {
            if let Value::Text(s) = key {
                let ss = s.as_str();
                match ss {
                    "alg" => att.attstmt_alg = util::cbor_value_to_num(val)?,
                    "sig" => att.attstmt_sig = util::cbor_value_to_vec_u8(val)?,
                    "x5c" => att.attstmt_x5c = util::cbor_value_to_vec_bytes(val)?,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn parse_cbor_authdata(authdata: &[u8], attestation: &mut Attestation)->Result<(),String> {
    // copy
    attestation.auth_data = authdata.to_vec();

    let mut index = 0;

    // rpIdHash	(32)
    let clo_vec = |idx: usize, x: usize| (authdata[idx..idx + x].to_vec(), idx + x);

    let ret = clo_vec(index, 32);
    attestation.rpid_hash = ret.0;
    index = ret.1;

    // flags(1)
    let byte = authdata[index];
    attestation.flags_user_present_result = if let 0x01 = byte & 0x01 { true } else { false };
    attestation.flags_user_verified_result = if let 0x04 = byte & 0x04 { true } else { false };
    attestation.flags_attested_credential_data_included =
        if let 0x40 = byte & 0x40 { true } else { false };
    attestation.flags_extension_data_included = if let 0x80 = byte & 0x80 { true } else { false };
    index = index + 1;

    // signCount(4)
    let clo = |idx: usize, x: usize| {
        let mut rdr = Cursor::new(authdata[idx..idx + x].to_vec());
        (rdr.read_u32::<BigEndian>().unwrap(), idx + x)
    };
    let ret = clo(index, 4);
    attestation.sign_count = ret.0;
    index = ret.1;

    // aaguid(16)
    let ret = clo_vec(index, 16);
    attestation.aaguid = ret.0;
    index = ret.1;

    // credentialIdLength(2)
    let clo = |idx: usize, x: usize| {
        let mut rdr = Cursor::new(authdata[idx..idx + x].to_vec());
        (rdr.read_u16::<BigEndian>().unwrap(), idx + x)
    };
    let ret = clo(index, 2);
    let len = ret.0;
    index = ret.1;

    // credentialId(credentialIdLength)
    let ret = clo_vec(index, len as usize);
    attestation.credential_descriptor.id = ret.0;
    index = ret.1;

    if attestation.flags_attested_credential_data_included {
        let slice = authdata[index..authdata.len()].to_vec();
        let cbor = serde_cbor::from_slice(&slice).unwrap();
        attestation.credential_publickey = attestation.credential_publickey.get(&cbor);
    }
    Ok(())
}

pub fn parse_cbor(bytes: &[u8]) -> Result<Attestation, String> {
    let mut attestation = Attestation::default();
    let maps = util::cbor_bytes_to_map(bytes)?;
    for (key, val) in &maps {
        if let Value::Integer(member) = key {
            match member {
                0x01 => {
                    if let Value::Text(s) = val {
                        attestation.fmt = s.to_string();
                    }
                }
                0x02 => {
                    if let Value::Bytes(xs) = val {
                        parse_cbor_authdata(xs, &mut attestation)?;
                    }
                }
                0x03 => {
                    parse_cbor_att_stmt(val, &mut attestation)?;
                }
                _ => println!("- anything error"),
            }
        }
    }
    Ok(attestation)
}
