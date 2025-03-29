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
    let cdh = params.client_data_hash.to_value();

    // 0x02 : rp
    let rp = Value::Map(vec![
        ("id".to_value(), params.rp_id.to_value()),
        ("name".to_value(), params.rp_name.to_value()),
    ]);

    // 0x03 : user
    // user id
    let user_id = if params.user_id.is_empty() {
        vec![0x00]
    } else {
        params.user_id.to_vec()
    };

    // user name
    let user_name = if params.user_name.is_empty() {
        " ".to_string()
    } else {
        params.user_name.to_string()
    };

    // displayName
    let display_name = if params.user_display_name.is_empty() {
        " ".to_string()
    } else {
        params.user_display_name.to_string()
    };

    let user = Value::Map(vec![
        ("id".to_value(), user_id.to_value()),
        ("name".to_value(), user_name.to_value()),
        ("displayName".to_value(), display_name.to_value()),
    ]);


    // 0x04 : pubKeyCredParams
    let pub_key_cred_params_vec = params
        .key_types
        .iter()
        .map(|key_type| {
            let pub_key_cred_params_val = vec![
                ("alg".to_value(), (*key_type as i64).to_value() ),
                ("type".to_value(), "public-key".to_value()),
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
                    ("id".to_value(), credential_id.to_value()),
                    ("type".to_value(), "public-key".to_value()),
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
                    map.push((ext.to_string().to_value(), x.to_value()));
                }
                Extension::CredProtect(n) => {
                    map.push((
                        ext.to_string().to_value(),
                        (n.unwrap() as i64).to_value()
                    ));
                }
                Extension::HmacSecret(n)
                | Extension::LargeBlobKey((n, _))
                | Extension::MinPinLength((n, _)) => {
                    map.push((ext.to_string().to_value(), n.unwrap().to_value()));
                }
            };
        }
        Some(Value::Map(map))
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
        options_val.push(("rk".to_value(), params.option_rk.to_value()));
        if let Some(v) = params.option_up {
            options_val.push(("up".to_value(), v.to_value()));
        }
        if let Some(v) = params.option_uv {
            options_val.push(("uv".to_value(), v.to_value()));
        }
        Value::Map(options_val)
    };

    // pinAuth(0x08)
    let pin_auth = {
        if !params.pin_auth.is_empty() {
            Some(params.pin_auth.to_value())
        } else {
            None
        }
    };

    // 0x09:pinProtocol
    let pin_protocol = 1.to_value();

    // create cbor object
    let mut make_credential = vec![
        (0x01.to_value(), cdh),
        (0x02.to_value(), rp),
        (0x03.to_value(), user),
        (0x04.to_value(), pub_key_cred_params),
    ];

    if !params.exclude_list.is_empty() {
        make_credential.push((0x05.to_value(), exclude_list));
    }
    if let Some(x) = extensions {
        make_credential.push((0x06.to_value(), x));
    }
    make_credential.push((0x07.to_value(), options));
    if let Some(x) = pin_auth {
        make_credential.push((0x08.to_value(), x));
        make_credential.push((0x09.to_value(), pin_protocol));
    }

    common::to_payload(make_credential, ctapdef::AUTHENTICATOR_MAKE_CREDENTIAL)
}
