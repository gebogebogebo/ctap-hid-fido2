use super::make_credential_params::{CredentialSupportedKeyType, Extension};
use crate::ctapdef;
use crate::util;
use anyhow::Result;
use ciborium::value::Value;
use ciborium::cbor;

#[derive(Debug, Default)]
pub struct Params {
    pub rp_id: String,
    pub rp_name: String,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
    pub exclude_list: Vec<Vec<u8>>,
    pub option_rk: bool,
    pub option_up: Option<bool>,
    pub option_uv: Option<bool>,
    pub client_data_hash: Vec<u8>,
    pub pin_auth: Vec<u8>,
    pub key_types: Vec<CredentialSupportedKeyType>,
}

impl Params {
    pub fn new(rp_id: &str, challenge: Vec<u8>, user_id: Vec<u8>) -> Params {
        Params {
            rp_id: rp_id.to_string(),
            user_id: user_id.to_vec(),
            client_data_hash: util::create_clientdata_hash(challenge),
            key_types: vec![CredentialSupportedKeyType::Ecdsa256],
            ..Default::default()
        }
    }
}

pub fn create_payload(params: Params, extensions: Option<&Vec<Extension>>) -> Result<Vec<u8>> {
    // 0x01 : clientDataHash
    let cdh = Value::Bytes(params.client_data_hash);

    // 0x02 : rp
    let rp = cbor!({
        "id" => params.rp_id,
        "name" => params.rp_name,
    })?;

    // 0x03 : user
    // user id
    let user_id = {
        if !params.user_id.is_empty() {
            params.user_id.to_vec()
        } else {
            vec![0x00]
        }
    };

    // user name
    let user_name = {
        if !params.user_name.is_empty() {
            params.user_name.to_string()
        } else {
            " ".to_string()
        }
    };

    // displayName
    let display_name = {
        if !params.user_display_name.is_empty() {
            params.user_display_name.to_string()
        } else {
            " ".to_string()
        }
    };

    let user = cbor!({
        "id" => Value::Bytes(user_id),
        "name" => user_name,
        "displayName" => display_name,
    })?;

    // 0x04 : pubKeyCredParams
    let pub_key_cred_params_vec = params
        .key_types
        .iter()
        .map(|key_type| {
            let pub_key_cred_params_val = vec![
                (Value::Text("alg".to_string()), Value::Integer((*key_type as i64).into())),
                (Value::Text("type".to_string()), Value::Text("public-key".to_string())),
            ];
            Value::Map(pub_key_cred_params_val)
        })
        .collect();

    let pub_key_cred_params = Value::Array(pub_key_cred_params_vec);

    // TODO これのテストをやりたい
    // 0x05 : excludeList
    let exclude_list = Value::Array(
        params
            .exclude_list
            .iter()
            .cloned()
            .map(|credential_id| {
                let exclude_list_val = vec![
                    (Value::Text(("id").to_string()), Value::Bytes(credential_id)),
                    (Value::Text(("type").to_string()), Value::Text(("public-key").to_string())),
                ];
                Value::Map(exclude_list_val)
            })
            .collect(),
    );

    // 0x06 : extensions
    let extensions = if let Some(extensions) = extensions {
        let mut map = Vec::new();
        for ext in extensions {
            match *ext {
                Extension::CredBlob((ref n, _)) => {
                    let x = n.clone().unwrap();
                    map.push((Value::Text(ext.to_string()), Value::Bytes(x)));
                }
                Extension::CredProtect(n) => {
                    map.push((
                        Value::Text(ext.to_string()),
                        Value::Integer((n.unwrap() as i64).into()),
                    ));
                }
                Extension::HmacSecret(n)
                | Extension::LargeBlobKey((n, _))
                | Extension::MinPinLength((n, _)) => {
                    map.push((Value::Text(ext.to_string()), Value::Bool(n.unwrap())));
                }
            };
        }
        Some(cbor!(map)?)
    } else {
        None
    };

    /*
    let user_id = {
        if let Some(rkp) = user_entity {
            rkp.id.to_vec()
        } else {
            [].to_vec()
        }
    };
    */

    // 0x07 : options
    let options = {
        let mut options_val = Vec::new();
        options_val.push((Value::Text("rk".to_string()), Value::Bool(params.option_rk)));
        if let Some(v) = params.option_up {
            options_val.push((Value::Text("up".to_string()), Value::Bool(v)));
        }
        if let Some(v) = params.option_uv {
            options_val.push((Value::Text("uv".to_string()), Value::Bool(v)));
        }
        Value::Map(options_val)
    };

    // pinAuth(0x08)
    let pin_auth = {
        if !params.pin_auth.is_empty() {
            Some(Value::Bytes(params.pin_auth))
        } else {
            None
        }
    };

    // 0x09:pinProtocol
    let pin_protocol = cbor!(1)?;

    // create cbor object
    let mut make_credential = vec![
        (cbor!(0x01)?, cdh),
        (cbor!(0x02)?, rp),
        (cbor!(0x03)?, user),
        (cbor!(0x04)?, pub_key_cred_params),
    ];

    if !params.exclude_list.is_empty() {
        make_credential.push((cbor!(0x05)?, exclude_list));
    }
    if let Some(x) = extensions {
        make_credential.push((cbor!(0x06)?, x));
    }
    make_credential.push((cbor!(0x07)?, options));
    if let Some(x) = pin_auth {
        make_credential.push((cbor!(0x08)?, x));
        make_credential.push((cbor!(0x09)?, pin_protocol));
    }

    // client_pin_command.rsとの比較に基づく修正
    // シリアライズ済みのCBORデータを二重にシリアライズせず、直接Value::Mapとして使用する
    let cbor = Value::Map(make_credential);

    // Command - authenticatorMakeCredential (0x01)
    let mut payload = [ctapdef::AUTHENTICATOR_MAKE_CREDENTIAL].to_vec();
    let mut serialized = Vec::new();
    ciborium::ser::into_writer(&cbor, &mut serialized)?;
    payload.append(&mut serialized);

    Ok(payload)
}
