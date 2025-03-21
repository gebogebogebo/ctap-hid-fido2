use super::make_credential_params::{CredentialSupportedKeyType, Extension};
use crate::ctapdef;
use crate::util;
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;

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

pub fn create_payload(params: Params, extensions: Option<&Vec<Extension>>) -> Vec<u8> {
    // 0x01 : clientDataHash
    let cdh = Value::Bytes(params.client_data_hash);

    // 0x02 : rp
    let mut rp_val = Vec::new();
    rp_val.push((
        Value::Text("id".to_string()),
        Value::Text(params.rp_id.to_string()),
    ));
    rp_val.push((
        Value::Text("name".to_string()),
        Value::Text(params.rp_name.to_string()),
    ));

    let rp_btree: BTreeMap<Value, Value> = rp_val.into_iter().collect();
    let rp = Value::Map(rp_btree);

    // 0x03 : user
    let mut user_val = Vec::new();
    // user id
    {
        let user_id = {
            if !params.user_id.is_empty() {
                params.user_id.to_vec()
            } else {
                vec![0x00]
            }
        };
        user_val.push((Value::Text("id".to_string()), Value::Bytes(user_id)));
    }
    // user name
    {
        let user_name = {
            if !params.user_name.is_empty() {
                params.user_name.to_string()
            } else {
                " ".to_string()
            }
        };
        user_val.push((Value::Text("name".to_string()), Value::Text(user_name)));
    }
    // displayName
    {
        let display_name = {
            if !params.user_display_name.is_empty() {
                params.user_display_name.to_string()
            } else {
                " ".to_string()
            }
        };
        user_val.push((
            Value::Text("displayName".to_string()),
            Value::Text(display_name),
        ));
    }

    let user_btree: BTreeMap<Value, Value> = user_val.into_iter().collect();
    let user = Value::Map(user_btree);

    // 0x04 : pubKeyCredParams
    let pub_key_cred_params_vec = params
        .key_types
        .iter()
        .map(|key_type| {
            let mut pub_key_cred_params_val = Vec::new();
            pub_key_cred_params_val.push((
                Value::Text("alg".to_string()),
                Value::Integer(*key_type as i128),
            ));
            pub_key_cred_params_val.push((
                Value::Text("type".to_string()),
                Value::Text("public-key".to_string()),
            ));

            let pub_key_cred_params_btree: BTreeMap<Value, Value> = pub_key_cred_params_val.into_iter().collect();
            Value::Map(pub_key_cred_params_btree)
        })
        .collect();

    let pub_key_cred_params = Value::Array(pub_key_cred_params_vec);

    // 0x05 : excludeList
    let exclude_list = Value::Array(
        params
            .exclude_list
            .iter()
            .cloned()
            .map(|credential_id| {
                let mut exclude_list_val = Vec::new();
                exclude_list_val.push((Value::Text("id".to_string()), Value::Bytes(credential_id)));
                exclude_list_val.push((
                    Value::Text("type".to_string()),
                    Value::Text("public-key".to_string()),
                ));
                let exclude_list_btree: BTreeMap<Value, Value> = exclude_list_val.into_iter().collect();
                Value::Map(exclude_list_btree)
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
                        Value::Integer(n.unwrap() as i128),
                    ));
                }
                Extension::HmacSecret(n)
                | Extension::LargeBlobKey((n, _))
                | Extension::MinPinLength((n, _)) => {
                    map.push((Value::Text(ext.to_string()), Value::Bool(n.unwrap())));
                }
            };
        }
        let map_btree: BTreeMap<Value, Value> = map.into_iter().collect();
        Some(Value::Map(map_btree))
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
        let options_btree: BTreeMap<Value, Value> = options_val.into_iter().collect();
        Value::Map(options_btree)
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
    let pin_protocol = Value::Integer(1);

    // create cbor object
    let mut make_credential = Vec::new();
    make_credential.push((Value::Integer(0x01), cdh));
    make_credential.push((Value::Integer(0x02), rp));
    make_credential.push((Value::Integer(0x03), user));
    make_credential.push((Value::Integer(0x04), pub_key_cred_params));
    if !params.exclude_list.is_empty() {
        make_credential.push((Value::Integer(0x05), exclude_list));
    }
    if let Some(x) = extensions {
        make_credential.push((Value::Integer(0x06), x));
    }
    make_credential.push((Value::Integer(0x07), options));
    if let Some(x) = pin_auth {
        make_credential.push((Value::Integer(0x08), x));
        make_credential.push((Value::Integer(0x09), pin_protocol));
    }
    let make_credential_btree: BTreeMap<Value, Value> = make_credential.into_iter().collect();
    let cbor = Value::Map(make_credential_btree);

    // Command - authenticatorMakeCredential (0x01)
    let mut payload = [ctapdef::AUTHENTICATOR_MAKE_CREDENTIAL].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());

    payload
}
