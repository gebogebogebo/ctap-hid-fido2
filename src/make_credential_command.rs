
use serde_cbor::Value;
use std::collections::BTreeMap;
use serde_cbor::to_vec;
use crate::util;

pub struct Params
{
    pub rp_id : String,
    pub rp_name : String,
    pub user_id : Vec<u8>,
    pub user_name : String,
    pub user_display_name : String,
    pub option_rk : bool,
    pub option_uv : bool,
    pub client_data_hash : Vec<u8>,
    pub pin_auth : Vec<u8>,
}

impl Params {
    pub fn new(rp_id:&str,challenge:Vec<u8>,user_id:Vec<u8>) -> Params {
        Params {
            rp_id : rp_id.to_string(),
            rp_name : "".to_string(),
            user_id : user_id.to_vec(),
            user_name : "".to_string(),
            user_display_name : "".to_string(),
            option_rk : false,
            option_uv : false,
            client_data_hash : util::create_clientdata_hash(challenge),
            pin_auth : [].to_vec(),
        }
    }
}

pub fn create_payload(params : Params) -> Vec<u8>{
    // 0x01 : clientDataHash
    let cdh = Value::Bytes(params.client_data_hash);

    // 0x02 : rp
    let mut rp_val = BTreeMap::new();
    rp_val.insert(Value::Text("id".to_string()),Value::Text(params.rp_id.to_string()));
    rp_val.insert(Value::Text("name".to_string()),Value::Text(params.rp_name.to_string()));
    let rp = Value::Map(rp_val);

    // 0x03 : user
    let mut user_val = BTreeMap::new();
    user_val.insert(Value::Text("id".to_string()),Value::Bytes(params.user_id));
    if params.user_name.len() > 0 {
        user_val.insert(Value::Text("name".to_string()),Value::Text(params.user_name.to_string()));
    }
    if params.user_display_name.len() > 0 {
        user_val.insert(Value::Text("displayName".to_string()),Value::Text(params.user_display_name.to_string()));
    }
    let user = Value::Map(user_val);

    // 0x04 : pubKeyCredParams
    let mut pub_key_cred_params_val = BTreeMap::new();
    pub_key_cred_params_val.insert(Value::Text("alg".to_string()),Value::Integer(-7));
    pub_key_cred_params_val.insert(Value::Text("type".to_string()),Value::Text("public-key".to_string()));
    let tmp = Value::Map(pub_key_cred_params_val);
    let pub_key_cred_params = Value::Array(vec![tmp]);

    // pinAuth(0x08)
    let pin_auth = {
        if params.pin_auth.len() > 0 {
            Some(Value::Bytes(params.pin_auth))
        }else{
            None
        }
    };

    // 0x09:pinProtocol
    let pin_protocol = Value::Integer(1);

    // create cbor object
    let mut make_credential = BTreeMap::new();
    make_credential.insert(Value::Integer(0x01),cdh);
    make_credential.insert(Value::Integer(0x02),rp);
    make_credential.insert(Value::Integer(0x03),user);
    make_credential.insert(Value::Integer(0x04),pub_key_cred_params);
    if let Some(x) = pin_auth {
        make_credential.insert(Value::Integer(0x08),x);
        make_credential.insert(Value::Integer(0x09),pin_protocol);
    }
    let cbor = Value::Map(make_credential);

    // Command - authenticatorMakeCredential (0x01)
    let mut payload = [0x01].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());

    payload
}
