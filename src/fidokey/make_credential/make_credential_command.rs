use super::make_credential_params::{CredentialSupportedKeyType, Extension};
use crate::ctapdef;
use crate::fidokey::common;
use crate::util;
use crate::util_ciborium::ToValue;
use anyhow::Result;
use ciborium::value::Value;

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
    pub fn new(rp_id: &str, challenge: Vec<u8>, user_id: Vec<u8>) -> Self {
        Self {
            rp_id: rp_id.to_string(),
            user_id,
            client_data_hash: util::create_clientdata_hash(challenge),
            key_types: vec![CredentialSupportedKeyType::Ecdsa256],
            ..Default::default()
        }
    }
}

pub fn create_payload(params: Params, extensions: Option<&Vec<Extension>>, pin_protocol_version: u8) -> Result<Vec<u8>> {
    // 0x01 : clientDataHash
    let cdh = params.client_data_hash.to_value();

    // 0x02 : rp
    let rp = vec![
        ("id".to_value(), params.rp_id.to_value()),
        ("name".to_value(), params.rp_name.to_value()),
    ]
    .to_value();

    // 0x03 : user
    let user_id = if params.user_id.is_empty() {
        vec![0x00]
    } else {
        params.user_id
    };
    let user_name = if params.user_name.is_empty() {
        " ".to_string()
    } else {
        params.user_name
    };
    let display_name = if params.user_display_name.is_empty() {
        " ".to_string()
    } else {
        params.user_display_name
    };
    let user = vec![
        ("id".to_value(), user_id.to_value()),
        ("name".to_value(), user_name.to_value()),
        ("displayName".to_value(), display_name.to_value()),
    ]
    .to_value();

    // 0x04 : pubKeyCredParams
    let pub_key_cred_params = create_pub_key_cred_params(&params.key_types);
    // 0x05 : excludeList
    let exclude_list = create_exclude_list(&params.exclude_list);
    // 0x06 : extensions
    let ext_val = create_extensions(extensions);
    // 0x07 : options
    let options = create_options(params.option_rk, params.option_up, params.option_uv);
    // 0x08 : pinAuth
    let pin_auth = if params.pin_auth.is_empty() {
        None
    } else {
        Some(params.pin_auth.to_value())
    };

    let mut make_credential = vec![
        (0x01.to_value(), cdh),
        (0x02.to_value(), rp),
        (0x03.to_value(), user),
        (0x04.to_value(), pub_key_cred_params),
    ];

    if !params.exclude_list.is_empty() {
        make_credential.push((0x05.to_value(), exclude_list));
    }
    if let Some(ext) = ext_val {
        make_credential.push((0x06.to_value(), ext));
    }
    make_credential.push((0x07.to_value(), options));
    if let Some(pin) = pin_auth {
        make_credential.push((0x08.to_value(), pin));
        // 0x09: pinProtocol
        make_credential.push((0x09.to_value(), pin_protocol_version.to_value()));
    }

    common::to_payload(make_credential, ctapdef::AUTHENTICATOR_MAKE_CREDENTIAL)
}

fn create_pub_key_cred_params(key_types: &[CredentialSupportedKeyType]) -> Value {
    let params_vec: Vec<Value> = key_types
        .iter()
        .map(|&key_type| {
            vec![
                ("alg".to_value(), (key_type as i64).to_value()),
                ("type".to_value(), "public-key".to_value()),
            ]
            .to_value()
        })
        .collect();
    params_vec.to_value()
}

fn create_exclude_list(credential_ids: &[Vec<u8>]) -> Value {
    let list: Vec<Value> = credential_ids
        .iter()
        .map(|id| {
            vec![
                ("id".to_value(), id.to_value()),
                ("type".to_value(), "public-key".to_value()),
            ]
            .to_value()
        })
        .collect();
    list.to_value()
}

fn create_extensions(extensions: Option<&Vec<Extension>>) -> Option<Value> {
    extensions.map(|exts| {
        let map: Vec<(Value, Value)> = exts
            .iter()
            .map(|ext| match ext {
                Extension::CredBlob((n, _)) => {
                    (ext.to_string().to_value(), n.clone().unwrap().to_value())
                }
                Extension::CredProtect(n) => {
                    (ext.to_string().to_value(), (n.unwrap() as i64).to_value())
                }
                Extension::HmacSecret(n)
                | Extension::LargeBlobKey((n, _))
                | Extension::MinPinLength((n, _)) => {
                    (ext.to_string().to_value(), n.unwrap().to_value())
                }
            })
            .collect();
        map.to_value()
    })
}

fn create_options(rk: bool, up: Option<bool>, uv: Option<bool>) -> Value {
    let mut options = vec![("rk".to_value(), rk.to_value())];
    if let Some(v) = up {
        options.push(("up".to_value(), v.to_value()));
    }
    if let Some(v) = uv {
        options.push(("uv".to_value(), v.to_value()));
    }
    options.to_value()
}
