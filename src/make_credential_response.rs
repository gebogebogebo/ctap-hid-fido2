use crate::make_credential_params;
use byteorder::{BigEndian, ReadBytesExt};
use serde_cbor::Value;
use std::io::Cursor;

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
        }
        _ => println!("- anything error"),
    }
}

fn parse_cbor_authdata(authdata: &[u8], attestation: &mut make_credential_params::Attestation) {
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
    //index = ret.1;

    /* PEND
    if (attestation.flags_attested_credentialdata_included) {
    }
    */
}

pub fn parse_cbor(bytes: &[u8]) -> Result<make_credential_params::Attestation, String> {
    let cbor: Value = serde_cbor::from_slice(bytes).unwrap();

    let mut attestation = Default::default();

    /*
    let mut attestation = make_credential_params::Attestation {
        fmt : String::from(""),
        rpid_hash: [].to_vec(),
        flags_user_present_result : false,
        flags_user_verified_result : false,
        flags_attested_credential_data_included : false,
        flags_extension_data_included : false,
        sign_count :0,
        aaguid : [].to_vec(),
        credential_id : [].to_vec(),
        credential_publickey : String::from(""),
        credential_publickey_byte : [].to_vec(),
        authdata : [].to_vec(),

        attstmt_alg : 0,
        attstmt_sig : [].to_vec(),
        attstmt_x5c : [].to_vec(),
    };
    */

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
