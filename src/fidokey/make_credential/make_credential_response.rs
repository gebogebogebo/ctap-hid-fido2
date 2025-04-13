use super::make_credential_params::{Attestation, Extension};
use super::CredentialProtectionPolicy;
use crate::public_key::PublicKey;
use crate::util_ciborium;
use crate::auth_data::Flags;
use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt};
use ciborium::value::Value;
use std::io::Cursor;

fn parse_cbor_att_stmt(obj: &Value, att: &mut Attestation) -> Result<()> {
    if let Some(map) = util_ciborium::extract_map_ref(obj).ok() {
        for (key, val) in map {
            if util_ciborium::is_text(key) {
                let key_text = util_ciborium::cbor_value_to_str(key)?;
                match key_text.as_str() {
                    "alg" => att.attstmt_alg = util_ciborium::cbor_value_to_num(val)?,
                    "sig" => att.attstmt_sig = util_ciborium::cbor_value_to_vec_u8(val)?,
                    "x5c" => att.attstmt_x5c = util_ciborium::cbor_value_to_vec_bytes(val)?,
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn parse_cbor_authdata(authdata: &[u8], attestation: &mut Attestation) -> Result<()> {
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
    attestation.flags = Flags::parse(byte)?;
    index += 1;

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

    // rest is cbor objects
    // - [0] credentialPublicKey
    // - [1] extensions
    let slice = if attestation.flags.attested_credential_data_included {
        let slice = &authdata[index..authdata.len()];
        match ciborium::de::from_reader(Cursor::new(slice)) {
            Ok(value) => {
                attestation.credential_publickey = PublicKey::new_from_ciborium(&value)?;
                // Serialize to get the number of bytes of the public key part and the rest of the data
                let mut bytes = Vec::new();
                ciborium::ser::into_writer(&value, &mut bytes)?;
                slice[bytes.len()..].to_vec()
            },
            Err(_) => authdata[index..authdata.len()].to_vec(),
        }
    } else {
        authdata[index..authdata.len()].to_vec()
    };

    if attestation.flags.extension_data_included {
        //println!("{:02} - {:?}", slice.len(), util::to_hex_str(&slice));
        let maps = util_ciborium::cbor_bytes_to_map(&slice)?;
        for (key, val) in &maps {
            if util_ciborium::is_text(key) {
                let member = util_ciborium::cbor_value_to_str(key)?;
                if member == Extension::HmacSecret(None).to_string() {
                    let v = util_ciborium::cbor_value_to_bool(val)?;
                    attestation.extensions.push(Extension::HmacSecret(Some(v)));
                } else if member == Extension::CredProtect(None).to_string() {
                    let v: u32 = util_ciborium::cbor_value_to_num(val)?;
                    attestation.extensions.push(Extension::CredProtect(Some(
                        CredentialProtectionPolicy::from(v),
                    )));
                } else if member == Extension::MinPinLength((None, None)).to_string() {
                    let v: u8 = util_ciborium::cbor_value_to_num(val)?;
                    attestation
                        .extensions
                        .push(Extension::MinPinLength((None, Some(v))));
                } else if member == Extension::CredBlob((None, None)).to_string() {
                    let v = util_ciborium::cbor_value_to_bool(val)?;
                    attestation
                        .extensions
                        .push(Extension::CredBlob((None, Some(v))));
                } else {
                    println!("Anything Extension!");
                }
            }
        }
    };

    Ok(())
}

pub fn parse_cbor(bytes: &[u8]) -> Result<Attestation> {
    let mut attestation = Attestation::default();
    let maps = util_ciborium::cbor_bytes_to_map(bytes)?;
    for (key, val) in &maps {
        if util_ciborium::is_integer(key) {
            match util_ciborium::integer_to_i64(key)? {
                0x01 => attestation.fmt = util_ciborium::cbor_value_to_str(val)?,
                0x02 => parse_cbor_authdata(&util_ciborium::cbor_value_to_vec_u8(val)?, &mut attestation)?,
                0x03 => parse_cbor_att_stmt(val, &mut attestation)?,
                0x05 => {
                    let lbk = util_ciborium::cbor_value_to_vec_u8(val)?;
                    attestation
                        .extensions
                        .push(Extension::LargeBlobKey((None, Some(lbk))));
                }
                _ => println!("- anything error"),
            }
        }
    }
    Ok(attestation)
}
