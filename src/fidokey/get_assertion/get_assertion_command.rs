use super::get_assertion_params::Extension;
use crate::ctapdef;
use crate::fidokey::common;
use crate::hmac_ext::HmacExt;
use crate::util;
use crate::util_ciborium::ToValue;
use anyhow::Result;
use ciborium::value::Value;

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
    pin_protocol_version: u8,
) -> Result<Vec<u8>> {
    // 0x01 : rpid
    let rpid = params.rp_id.to_value();

    // 0x02 : clientDataHash
    let cdh = params.client_data_hash.to_value();

    // 0x03 : allowList
    let allow_list = create_allow_list(&params.allowlist_credential_ids);

    // 0x04 : extensions
    let ext_val = create_extensions(extensions, hmac_ext);

    // 0x05 : options
    let options = create_options(params.option_up, params.option_uv);

    // 0x06 : pinAuth
    let pin_auth = if params.pin_auth.is_empty() {
        None
    } else {
        Some(params.pin_auth.to_value())
    };

    // create cbor object
    let mut get_assertion = vec![(1.to_value(), rpid), (2.to_value(), cdh)];

    if !params.allowlist_credential_ids.is_empty() {
        get_assertion.push((3.to_value(), allow_list));
    }

    if let Some(ext) = ext_val {
        get_assertion.push((4.to_value(), ext));
    }

    get_assertion.push((5.to_value(), options));

    if let Some(pin) = pin_auth {
        get_assertion.push((6.to_value(), pin));
        // pinProtocol(0x07)
        get_assertion.push((7.to_value(), pin_protocol_version.to_value()));
    }

    common::to_payload(get_assertion, ctapdef::AUTHENTICATOR_GET_ASSERTION)
}

fn create_allow_list(credential_ids: &[Vec<u8>]) -> Value {
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

fn create_extensions(
    extensions: Option<&Vec<Extension>>,
    hmac_ext: Option<HmacExt>,
) -> Option<Value> {
    let mut ext_val = Vec::new();

    // HMAC Secret Extension
    if let Some(hmac_ext) = hmac_ext {
        let tmp = hmac_ext.shared_secret.public_key.to_value_cib().unwrap();
        let param = vec![
            // keyAgreement(0x01)
            (1.to_value(), tmp),
            // saltEnc(0x02)
            (2.to_value(), hmac_ext.salt_enc.to_value()),
            // saltAuth(0x03)
            (3.to_value(), hmac_ext.salt_auth.to_value()),
        ];

        ext_val.push((
            Extension::HmacSecret(None).to_string().to_value(),
            param.to_value(),
        ));
    }

    if let Some(extensions) = extensions {
        for ext in extensions {
            match *ext {
                Extension::HmacSecret(_) | Extension::HmacSecret2(_) => (),
                Extension::LargeBlobKey((n, _)) | Extension::CredBlob((n, _)) => {
                    ext_val.push((ext.to_string().to_value(), n.unwrap().to_value()));
                }
            };
        }
    }

    if ext_val.is_empty() {
        None
    } else {
        Some(ext_val.to_value())
    }
}

fn create_options(up: bool, uv: Option<bool>) -> Value {
    let mut options = vec![("up".to_value(), up.to_value())];
    if let Some(v) = uv {
        options.push(("uv".to_value(), v.to_value()));
    }
    options.to_value()
}
