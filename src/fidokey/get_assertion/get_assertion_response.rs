use super::get_assertion_params;
use super::get_assertion_params::Extension;
use crate::auth_data::Flags;
use crate::encrypt::enc_aes256_cbc;
use crate::encrypt::shared_secret::SharedSecret;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::util_ciborium;
use anyhow::Result;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;

fn parse_cbor_authdata(
    authdata: Vec<u8>,
    ass: &mut get_assertion_params::Assertion,
    shared_secret: Option<&SharedSecret>,
) -> Result<()> {
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
        // TODO この if 文に入るケースのテストをしていないので注意！
        
        let slice = &authdata[index..authdata.len()];
        // skip device credential publicKey
        let bytes_read = util_ciborium::skip_next_cbor_item(slice);
        slice[bytes_read..].to_vec()
    } else {
        authdata[index..authdata.len()].to_vec()
    };

    if ass.flags.extension_data_included {
        let maps = util_ciborium::cbor_bytes_to_map(&slice)?;
        for (key, val) in &maps {
            if util_ciborium::is_text(key) {
                let member = util_ciborium::cbor_value_to_str(key)?;
                if member == Extension::HmacSecret(None).to_string() {
                    // 12.5. HMAC Secret Extension (hmac-secret)
                    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-hmac-secret-extension

                    // The hmac-secret is created in Authenticator as follows.
                    // > One salt case: "hmac-secret": encrypt(shared secret, output1)
                    let hmac_secret = util_ciborium::cbor_value_to_vec_u8(val)?;

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
                } else if member == Extension::CredBlob((None, None)).to_string() {
                    let cred_blob = util_ciborium::cbor_value_to_vec_u8(val)?;
                    ass.extensions
                        .push(Extension::CredBlob((None, Some(cred_blob))));
                } else {
                    println!("Anything Extension!");
                }
            }
        }
    };
    Ok(())
}

pub fn parse_cbor(
    bytes: &[u8],
    shared_secret: Option<SharedSecret>,
) -> Result<get_assertion_params::Assertion> {
    let mut ass = get_assertion_params::Assertion::default();
    let maps = util_ciborium::cbor_bytes_to_map(bytes)?;
    for (key, val) in &maps {
        if util_ciborium::is_integer(key) {
            match util_ciborium::integer_to_i64(key)? {
                0x01 => ass.credential_id = util_ciborium::cbor_get_bytes_from_map(val, "id")?,
                0x02 => {
                    if util_ciborium::is_bytes(val) {
                        let xs = util_ciborium::cbor_value_to_vec_u8(val)?;
                        parse_cbor_authdata(xs, &mut ass, shared_secret.as_ref())?;
                    }
                }
                0x03 => ass.signature = util_ciborium::cbor_value_to_vec_u8(val)?,
                0x04 => {
                    // PublicKeyCredentialUserEntityはまだserde_cbor::Valueを使用しているため、変換が必要
                    let serde_val = util_ciborium::ciborium_to_serde(val.clone())?;
                    ass.user = PublicKeyCredentialUserEntity::default()
                        .get_id(&serde_val)
                        .get_name(&serde_val)
                        .get_display_name(&serde_val)
                }
                0x05 => ass.number_of_credentials = util_ciborium::cbor_value_to_num(val)?,
                0x06 => (), // TODO userSelected
                0x07 => {
                    let lbk = util_ciborium::cbor_value_to_vec_u8(val)?;
                    ass.extensions
                        .push(Extension::LargeBlobKey((None, Some(lbk))));
                }
                _ => println!("- anything error"),
            }
        }
    }
    Ok(ass)
}
