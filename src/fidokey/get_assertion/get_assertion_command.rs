use super::get_assertion_params::Extension;
use crate::ctapdef;
use crate::hmac_ext::HmacExt;
use crate::util::{self, vec_to_btree_map};
use serde_cbor::to_vec;
use serde_cbor::Value;

#[derive(Debug, Default)]
pub struct Params {
    pub rp_id: String,
    pub client_data_hash: Vec<u8>,
    pub allowlist_credential_ids: Vec<Vec<u8>>,
    pub option_up: bool,
    pub option_uv: Option<bool>,
    pub pin_auth: Vec<u8>,
}

impl Params {
    pub fn new(rp_id: &str, challenge: Vec<u8>, credential_ids: Vec<Vec<u8>>) -> Params {
        Params {
            rp_id: rp_id.to_string(),
            client_data_hash: util::create_clientdata_hash(challenge),
            allowlist_credential_ids: credential_ids,
            ..Default::default()
        }
    }
}

pub fn create_payload(
    params: Params,
    extensions: Option<&Vec<Extension>>,
    hmac_ext: Option<HmacExt>,
) -> Vec<u8> {
    // 0x01 : rpid
    let rpid = Value::Text(params.rp_id.to_string());

    // 0x02 : clientDataHash
    let cdh = Value::Bytes(params.client_data_hash);

    // 0x03 : allowList
    let allow_list = {
        if !params.allowlist_credential_ids.is_empty() {
            let allow_list = Value::Array(
                params
                    .allowlist_credential_ids
                    .iter()
                    .cloned()
                    .map(|credential_id| {
                        let mut allow_list_val = Vec::new();
                        allow_list_val
                            .push((Value::Text("id".to_string()), Value::Bytes(credential_id)));
                        allow_list_val.push((
                            Value::Text("type".to_string()),
                            Value::Text("public-key".to_string()),
                        ));
                        Value::Map(vec_to_btree_map(allow_list_val))
                    })
                    .collect(),
            );
            Some(allow_list)
        } else {
            None
        }
    };

    // 0x04 : extensions
    let extensions = {
        let mut ext_val = Vec::new();

        // HMAC Secret Extension
        if let Some(hmac_ext) = hmac_ext {
            let mut param = Vec::new();

            // keyAgreement(0x01)
            let val = hmac_ext.shared_secret.public_key.to_value().unwrap();
            param.push((Value::Integer(0x01), val));

            // saltEnc(0x02)
            param.push((Value::Integer(0x02), Value::Bytes(hmac_ext.salt_enc)));

            // saltAuth(0x03)
            param.push((Value::Integer(0x03), Value::Bytes(hmac_ext.salt_auth)));

            ext_val.push((
                Value::Text(Extension::HmacSecret(None).to_string()),
                Value::Map(vec_to_btree_map(param)),
            ));
        }

        if let Some(extensions) = extensions {
            for ext in extensions {
                match *ext {
                    Extension::HmacSecret(_) => (),
                    Extension::LargeBlobKey((n, _)) | Extension::CredBlob((n, _)) => {
                        ext_val.push((Value::Text(ext.to_string()), Value::Bool(n.unwrap())));
                    }
                };
            }
        }
        if ext_val.is_empty() {
            None
        } else {
            Some(Value::Map(vec_to_btree_map(ext_val)))
        }
    };

    // 0x05 : options
    let mut options_val = Vec::new();
    options_val.push((Value::Text("up".to_string()), Value::Bool(params.option_up)));
    if let Some(v) = params.option_uv {
        options_val.push((Value::Text("uv".to_string()), Value::Bool(v)));
    }

    let options = Value::Map(vec_to_btree_map(options_val));

    // pinAuth(0x06)
    let pin_auth = {
        if !params.pin_auth.is_empty() {
            Some(Value::Bytes(params.pin_auth))
        } else {
            None
        }
    };

    // 0x07:pinProtocol
    let pin_protocol = Value::Integer(1);

    // create cbor object
    let mut get_assertion = Vec::new();
    get_assertion.push((Value::Integer(0x01), rpid));
    get_assertion.push((Value::Integer(0x02), cdh));
    if let Some(obj) = allow_list {
        get_assertion.push((Value::Integer(0x03), obj));
    }
    if let Some(extensions) = extensions {
        get_assertion.push((Value::Integer(0x04), extensions));
    }
    get_assertion.push((Value::Integer(0x05), options));
    if let Some(x) = pin_auth {
        get_assertion.push((Value::Integer(0x06), x));
        get_assertion.push((Value::Integer(0x07), pin_protocol));
    }
    let cbor = Value::Map(vec_to_btree_map(get_assertion));

    // Command - authenticatorGetAssertion (0x02)
    let mut payload = [ctapdef::AUTHENTICATOR_GET_ASSERTION].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());

    payload
}
