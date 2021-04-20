#[allow(unused_imports)]
use crate::util;

use crate::ctapdef;
use crate::pintoken;
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;

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
) -> Vec<u8> {
    let mut map = BTreeMap::new();

    if let Some(sub_command) = sub_command {
        // modality (0x01) = fingerprint (0x01)
        map.insert(Value::Integer(0x01), Value::Integer(0x01 as i128));

        // subCommand(0x02)
        let sub_cmd = Value::Integer(sub_command as i128);
        map.insert(Value::Integer(0x02), sub_cmd);

        if let Some(pin_token) = pin_token {
            // pinUvAuthProtocol(0x04)
            let pin_protocol = Value::Integer(1);
            map.insert(Value::Integer(0x04), pin_protocol);

            // pinUvAuthParam(0x05)
            let message = vec![sub_command as u8];
            //message.append(&mut sub_command_params_cbor.to_vec());
            let pin_uv_auth_param = pin_token.authenticate_v2(&message, 16);

            map.insert(Value::Integer(0x05), Value::Bytes(pin_uv_auth_param));
        }
    }else{
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
