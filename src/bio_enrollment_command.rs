#[allow(unused_imports)]
use crate::util;

use crate::ctapdef;
use crate::pintoken;
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;
use crate::bio_enrollment_params::{TemplateInfo};

#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SubCommand {
    EnrollBegin = 0x01,
    EnrollCaptureNextSample = 0x02,
    CancelCurrentEnrollment = 0x03,
    EnumerateEnrollments = 0x04,
    SetFriendlyName = 0x05,
    RemoveEnrollment = 0x06,
    GetFingerprintSensorInfo = 0x07,
}

pub fn create_payload(
    pin_token: Option<pintoken::PinToken>,
    sub_command: Option<SubCommand>,
    template_info: Option<TemplateInfo>,
    timeout_milliseconds: Option<u16>,
) -> Vec<u8> {
    let mut map = BTreeMap::new();

    if let Some(sub_command) = sub_command {
        // modality (0x01) = fingerprint (0x01)
        map.insert(Value::Integer(0x01), Value::Integer(0x01 as i128));

        // subCommand(0x02)
        let sub_cmd = Value::Integer(sub_command as i128);
        map.insert(Value::Integer(0x02), sub_cmd);

        // subCommandParams (0x03): Map containing following parameters
        let mut sub_command_params_cbor = Vec::new();
        if need_sub_command_param(sub_command) {
            let value = match sub_command {
                SubCommand::EnrollBegin | SubCommand::EnrollCaptureNextSample =>{
                    let param = to_value_timeout(template_info,timeout_milliseconds);
                    map.insert(Value::Integer(0x03), param.clone());
                    Some(param)
                },
                SubCommand::SetFriendlyName | SubCommand::RemoveEnrollment =>{
                    let param = to_value_template_info(template_info.unwrap());
                    map.insert(Value::Integer(0x03), param.clone());
                    Some(param)
                },
                _ => (None),
            };

            if let Some(v) = value {
                sub_command_params_cbor = to_vec(&v).unwrap();
            }
        }

        if let Some(pin_token) = pin_token {
            // pinUvAuthProtocol(0x04)
            let pin_protocol = Value::Integer(1);
            map.insert(Value::Integer(0x04), pin_protocol);

            // pinUvAuthParam (0x05)
            // - authenticate(pinUvAuthToken, fingerprint (0x01) || enumerateEnrollments (0x04)).
            let mut message = vec![0x01 as u8];
            message.append(&mut vec![sub_command as u8]);
            message.append(&mut sub_command_params_cbor.to_vec());
            let pin_uv_auth_param = pin_token.authenticate_v2(&message, 16);

            map.insert(Value::Integer(0x05), Value::Bytes(pin_uv_auth_param));
        }
    } else {
        // getModality (0x06)
        map.insert(Value::Integer(0x06), Value::Bool(true));
    }

    // create cbor
    let cbor = Value::Map(map);

    // create payload
    let mut payload = [ctapdef::AUTHENTICATOR_BIO_ENROLLMENT].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());
    payload
}

fn need_sub_command_param(sub_command: SubCommand) -> bool {
    sub_command == SubCommand::EnrollBegin ||
    sub_command == SubCommand::EnrollCaptureNextSample ||
    sub_command == SubCommand::SetFriendlyName ||
    sub_command == SubCommand::RemoveEnrollment
}

fn to_value_template_info(in_param: TemplateInfo) -> Value {
    let mut param = BTreeMap::new();
    param.insert(Value::Integer(0x01), Value::Bytes(in_param.template_id));
    if let Some(v) = in_param.template_friendly_name{
        param.insert(Value::Integer(0x02), Value::Text(v.to_string()));
    }
    Value::Map(param)
}

fn to_value_timeout(template_info: Option<TemplateInfo>,timeout_milliseconds: Option<u16>) -> Value {
    let mut param = BTreeMap::new();
    if let Some(v) = template_info{
        param.insert(Value::Integer(0x01), Value::Bytes(v.template_id));
    }
    if let Some(v) = timeout_milliseconds{
        param.insert(Value::Integer(0x03), Value::Integer(v as i128));
    }
    Value::Map(param)
}
