use super::super::sub_command_base::SubCommandBase;
use super::bio_enrollment_params::TemplateInfo;
use crate::{ctapdef, encrypt::enc_hmac_sha_256, pintoken::PinToken, util::vec_to_btree_map};
use anyhow::Result;
use serde_cbor::{to_vec, Value};
use strum_macros::EnumProperty;

#[allow(dead_code)]
#[derive(Debug, Clone, EnumProperty)]
pub enum SubCommand {
    #[strum(props(SubCommandId = "1"))]
    EnrollBegin(Option<u16>),
    #[strum(props(SubCommandId = "2"))]
    EnrollCaptureNextSample(TemplateInfo, Option<u16>),
    #[strum(props(SubCommandId = "3"))]
    CancelCurrentEnrollment,
    #[strum(props(SubCommandId = "4"))]
    EnumerateEnrollments,
    #[strum(props(SubCommandId = "5"))]
    SetFriendlyName(TemplateInfo),
    #[strum(props(SubCommandId = "6"))]
    RemoveEnrollment(TemplateInfo),
    #[strum(props(SubCommandId = "7"))]
    GetFingerprintSensorInfo,
}
impl SubCommandBase for SubCommand {
    fn has_param(&self) -> bool {
        matches!(
            self,
            SubCommand::EnrollBegin(_)
                | SubCommand::EnrollCaptureNextSample(_, _)
                | SubCommand::SetFriendlyName(_)
                | SubCommand::RemoveEnrollment(_)
        )
    }
}

pub fn create_payload(
    pin_token: Option<&PinToken>,
    sub_command: Option<SubCommand>,
    use_pre_bio_enrollment: bool,
) -> Result<Vec<u8>> {
    let mut map = Vec::new();

    match sub_command {
        Some(sub_command) => {
            // modality (0x01) = fingerprint (0x01)
            map.push((Value::Integer(0x01), Value::Integer(0x01_i128)));
            
            // subCommand(0x02)
            let sub_cmd_id = sub_command.id()?;
            map.push((Value::Integer(0x02), Value::Integer(sub_cmd_id as i128)));

            // subCommandParams (0x03): Map containing following parameters
            let mut sub_command_params_cbor = Vec::new();
            if sub_command.has_param() {
                let param = match sub_command {
                    SubCommand::EnrollBegin(timeout_milliseconds) => {
                        Some(to_value_timeout(None, timeout_milliseconds))
                    }
                    SubCommand::EnrollCaptureNextSample(ref template_info, timeout_milliseconds) => {
                        Some(to_value_timeout(Some(template_info), timeout_milliseconds))
                    }
                    SubCommand::SetFriendlyName(ref template_info)
                    | SubCommand::RemoveEnrollment(ref template_info) => {
                        Some(to_value_template_info(template_info))
                    }
                    _ => None,
                };
                if let Some(param) = param {
                    map.push((Value::Integer(0x03), param.clone()));
                    sub_command_params_cbor = to_vec(&param)?;
                }
            }

            if let Some(pin_token) = pin_token {
                // pinUvAuthProtocol(0x04)
                let pin_protocol = Value::Integer(1);
                map.push((Value::Integer(0x04), pin_protocol));

                // pinUvAuthParam (0x05)
                // - authenticate(pinUvAuthToken, fingerprint (0x01) || enumerateEnrollments (0x04)).
                let pin_uv_auth_param = {
                    let mut message = vec![0x01_u8];
                    message.append(&mut vec![sub_cmd_id]);
                    message.append(&mut sub_command_params_cbor.to_vec());
                    let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &message);
                    sig[0..16].to_vec()
                };

                map.push((Value::Integer(0x05), Value::Bytes(pin_uv_auth_param)));
            }
        },
        None => {
            // getModality (0x06)
            map.push((Value::Integer(0x06), Value::Bool(true)));
        }
    }

    // create cbor
    let cbor = Value::Map(vec_to_btree_map(map));

    // create payload
    let mut payload = if use_pre_bio_enrollment {
        [ctapdef::AUTHENTICATOR_BIO_ENROLLMENT_P].to_vec()
    } else {
        [ctapdef::AUTHENTICATOR_BIO_ENROLLMENT].to_vec()
    };
    payload.append(&mut to_vec(&cbor)?);
    Ok(payload)
}

fn to_value_template_info(in_param: &TemplateInfo) -> Value {
    let mut param = vec![(
        Value::Integer(0x01),
        Value::Bytes(in_param.template_id.clone()),
    )];
    if let Some(v) = in_param.template_friendly_name.clone() {
        param.push((Value::Integer(0x02), Value::Text(v)));
    }
    Value::Map(vec_to_btree_map(param))
}

fn to_value_timeout(
    template_info: Option<&TemplateInfo>,
    timeout_milliseconds: Option<u16>,
) -> Value {
    let mut param = Vec::new(); // この関数では条件分岐で追加するので維持
    if let Some(v) = template_info {
        param.push((Value::Integer(0x01), Value::Bytes(v.template_id.clone())));
    }
    if let Some(v) = timeout_milliseconds {
        param.push((Value::Integer(0x03), Value::Integer(v as i128)));
    }
    Value::Map(vec_to_btree_map(param))
}
