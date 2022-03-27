use crate::ctapdef;
use super::make_credential_params::{CredentialSupportedKeyType, Extension};
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
    pub option_rk: bool,
    pub option_up: Option<bool>,
    pub option_uv: Option<bool>,
    pub client_data_hash: Vec<u8>,
    pub pin_auth: Vec<u8>,
    pub key_type: CredentialSupportedKeyType,
}

impl Params {
    pub fn new(rp_id: &str, challenge: Vec<u8>, user_id: Vec<u8>) -> Params {
        Params {
            rp_id: rp_id.to_string(),
            user_id: user_id.to_vec(),
            client_data_hash: util::create_clientdata_hash(challenge),
            key_type: CredentialSupportedKeyType::Ecdsa256,
            ..Default::default()
        }
    }
}

pub fn create_payload(params: Params, extensions: Option<&Vec<Extension>>) -> Vec<u8> {
    // 0x01 : clientDataHash
    let cdh = Value::Bytes(params.client_data_hash);

    // 0x02 : rp
    let mut rp_val = BTreeMap::new();
    rp_val.insert(
        Value::Text("id".to_string()),
        Value::Text(params.rp_id.to_string()),
    );
    rp_val.insert(
        Value::Text("name".to_string()),
        Value::Text(params.rp_name.to_string()),
    );
    let rp = Value::Map(rp_val);

    // 0x03 : user
    let mut user_val = BTreeMap::new();
    // user id
    {
        let user_id = {
            if !params.user_id.is_empty() {
                params.user_id.to_vec()
            } else {
                vec![0x00]
            }
        };
        user_val.insert(Value::Text("id".to_string()), Value::Bytes(user_id));
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
        user_val.insert(Value::Text("name".to_string()), Value::Text(user_name));
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
        user_val.insert(
            Value::Text("displayName".to_string()),
            Value::Text(display_name),
        );
    }
    let user = Value::Map(user_val);

    // 0x04 : pubKeyCredParams
    let mut pub_key_cred_params_val = BTreeMap::new();
    pub_key_cred_params_val.insert(
        Value::Text("alg".to_string()),
        Value::Integer(params.key_type as i128),
    );
    pub_key_cred_params_val.insert(
        Value::Text("type".to_string()),
        Value::Text("public-key".to_string()),
    );
    let tmp = Value::Map(pub_key_cred_params_val);
    let pub_key_cred_params = Value::Array(vec![tmp]);

    // 0x06 : extensions
    let extensions = if let Some(extensions) = extensions {
        let mut map = BTreeMap::new();
        for ext in extensions {
            match *ext {
                Extension::CredProtect(n) => {
                    map.insert(
                        Value::Text(ext.to_string()),
                        Value::Integer(n.unwrap() as i128),
                    );
                }
                Extension::CredBlob(_) => (),
                Extension::MinPinLength(_) => (),
                Extension::HmacSecret(n) => {
                    map.insert(Value::Text(ext.to_string()), Value::Bool(n.unwrap()));
                }
            };
        }
        Some(Value::Map(map))
    } else {
        None
    };

    /*
    let user_id = {
        if let Some(rkp) = rkparam {
            rkp.id.to_vec()
        } else {
            [].to_vec()
        }
    };
    */

    // 0x07 : options
    let options = {
        let mut options_val = BTreeMap::new();
        options_val.insert(Value::Text("rk".to_string()), Value::Bool(params.option_rk));
        if let Some(v) = params.option_up {
            options_val.insert(Value::Text("up".to_string()), Value::Bool(v));
        }
        if let Some(v) = params.option_uv {
            options_val.insert(Value::Text("uv".to_string()), Value::Bool(v));
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
    let pin_protocol = Value::Integer(1);

    // create cbor object
    let mut make_credential = BTreeMap::new();
    make_credential.insert(Value::Integer(0x01), cdh);
    make_credential.insert(Value::Integer(0x02), rp);
    make_credential.insert(Value::Integer(0x03), user);
    make_credential.insert(Value::Integer(0x04), pub_key_cred_params);
    if let Some(x) = extensions {
        make_credential.insert(Value::Integer(0x06), x);
    }
    make_credential.insert(Value::Integer(0x07), options);
    if let Some(x) = pin_auth {
        make_credential.insert(Value::Integer(0x08), x);
        make_credential.insert(Value::Integer(0x09), pin_protocol);
    }
    let cbor = Value::Map(make_credential);

    // Command - authenticatorMakeCredential (0x01)
    let mut payload = [ctapdef::AUTHENTICATOR_MAKE_CREDENTIAL].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());

    payload
}
