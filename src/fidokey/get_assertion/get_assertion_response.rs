use crate::auth_data::Flags;
use crate::enc_aes256_cbc;
use super::get_assertion_params;
use super::get_assertion_params::Extension;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::ss::SharedSecret;
use crate::util;
use byteorder::{BigEndian, ReadBytesExt};
use serde_cbor::Value;
use std::io::Cursor;

fn parse_cbor_authdata(
    authdata: Vec<u8>,
    ass: &mut get_assertion_params::Assertion,
    shared_secret: Option<&SharedSecret>,
) -> Result<(), String> {
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
    ass.flags = Flags::parse(byte).unwrap();
    index += 1;

    // signCount(4)
    let clo = |idx: usize, x: usize| {
        let mut rdr = Cursor::new(authdata[idx..idx + x].to_vec());
        (rdr.read_u32::<BigEndian>().unwrap(), idx + x)
    };
    let ret = clo(index, 4);
    ass.sign_count = ret.0;
    index = ret.1;

    // rest is cbor objects
    // - [0] credentialPublicKey
    // - [1] extensions
    let slice = if ass.flags.attested_credential_data_included {
        let slice = &authdata[index..authdata.len()];
        let deserializer = serde_cbor::Deserializer::from_slice(slice);
        //
        slice[deserializer.byte_offset()..].to_vec()
    } else {
        authdata[index..authdata.len()].to_vec()
    };

    if ass.flags.extension_data_included {
        //println!("{:02} - {:?}", slice.len(), util::to_hex_str(&slice));
        let maps = util::cbor_bytes_to_map(&slice)?;
        for (key, val) in &maps {
            if let Value::Text(member) = key {
                if *member == Extension::HmacSecret(None).to_string() {
                    // 12.5. HMAC Secret Extension (hmac-secret)
                    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-hmac-secret-extension

                    // The hmac-secret is created in Authenticator as follows.
                    // > One salt case: "hmac-secret": encrypt(shared secret, output1)
                    let hmac_secret = util::cbor_value_to_vec_u8(val)?;

                    // decrypt hmac_secret -> output1
                    let output1 = enc_aes256_cbc::decrypt_message(
                        &shared_secret.as_ref().unwrap().secret,
                        &hmac_secret[0..32],
                    );

                    // The output1 is created in Authenticator as follows.
                    // >output1: HMAC-SHA-256(CredRandom, salt1)
                    // Can't access CredRandom since that is the secret the authenticator uses to derive credential specific private/public keys

                    let mut hmac_secret_0 = [0u8; 32];
                    hmac_secret_0.copy_from_slice(&output1[0..32]);
                    ass.extensions
                        .push(Extension::HmacSecret(Some(hmac_secret_0)));
                }
            }
        }
    };
    Ok(())
}

pub fn parse_cbor(
    bytes: &[u8],
    shared_secret: Option<SharedSecret>,
) -> Result<get_assertion_params::Assertion, String> {
    let mut ass = get_assertion_params::Assertion::default();
    let maps = util::cbor_bytes_to_map(bytes)?;
    for (key, val) in &maps {
        if let Value::Integer(member) = key {
            match member {
                0x01 => ass.credential_id = util::cbor_get_bytes_from_map(val, "id")?,
                0x02 => {
                    if let Value::Bytes(xs) = val {
                        parse_cbor_authdata(xs.to_vec(), &mut ass, shared_secret.as_ref())?;
                    }
                }
                0x03 => ass.signature = util::cbor_value_to_vec_u8(val)?,
                0x04 => {
                    ass.user = PublicKeyCredentialUserEntity::default()
                        .get_id(val)
                        .get_name(val)
                        .get_display_name(val)
                }
                0x05 => ass.number_of_credentials = util::cbor_value_to_num(val)?,
                _ => println!("- anything error"),
            }
        }
    }
    Ok(ass)
}
