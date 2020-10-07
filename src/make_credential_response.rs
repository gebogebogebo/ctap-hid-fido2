use crate::make_credential_params;
use crate::util;
use crate::cose;
use crate::p256;

use byteorder::{BigEndian, ReadBytesExt};
use serde_cbor::Value;
use std::io::Cursor;

fn parse_cbor_att_stmt(obj: &Value, att: &mut make_credential_params::Attestation) {
    if let Value::Map(xs) = obj {
        for (key, val) in xs {
            if let Value::Text(s) = key {
                let ss = s.as_str();
                match ss {
                    "alg" => att.attstmt_alg = util::cbor_cast_value(val).unwrap(),
                    "sig" => att.attstmt_sig = util::cbor_value_to_vec_u8(val).unwrap(),
                    "x5c" => att.attstmt_x5c = util::cbor_value_to_vec_bytes(val).unwrap(),
                    _ => {}
                }
            }
        }
    }
}

fn parse_cbor_member(
    member: i128,
    val: &Value,
    attestation: &mut make_credential_params::Attestation,
) {
    match member {
        1 => {
            // fmt (0x01)
            if let Value::Text(s) = val {
                attestation.fmt = s.to_string();
            }
        }
        2 => {
            // authData (0x02)
            if let Value::Bytes(xs) = val {
                parse_cbor_authdata(xs, attestation);
            }
        }
        3 => {
            // attStmt (0x03)
            parse_cbor_att_stmt(val, attestation);
        }
        _ => println!("- anything error"),
    }
}

fn parse_cbor_authdata(authdata: &[u8], attestation: &mut make_credential_params::Attestation) {
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
    attestation.credential_id = ret.0;
    index = ret.1;

    if attestation.flags_attested_credential_data_included {
        let slice = authdata[index..authdata.len()].to_vec();

        /*
        println!(
            "- public_key({:02})  = {:?}",
            slice.len(),
            util::to_hex_str(&slice)
        );
        */

        let cbor = serde_cbor::from_slice(&slice).unwrap();        
        let cose_key = cose::CoseKey::decode(&cbor).unwrap();

        let der_key = cose_key.convert_to_publickey_der();
        println!(
            "- public_key_der({:02})  = {:?}",
            der_key.len(),
            util::to_hex_str(&der_key)
        );

        //let p256_key = p256::P256Key::from_cose(&cose_key).unwrap();

        //attestation.credential_publickey = p256_key.bytes().to_vec();

    }
}

pub fn parse_cbor(bytes: &[u8]) -> Result<make_credential_params::Attestation, String> {
    let mut attestation = make_credential_params::Attestation::default();

    let cbor: Value = serde_cbor::from_slice(bytes).unwrap();
    if let Value::Map(map) = cbor {
        for (key, val) in &map {
            if let Value::Integer(member) = key {
                parse_cbor_member(*member, val, &mut attestation);
            }
        }
        Ok(attestation)
    } else {
        Err(String::from("parse error!"))
    }
}
