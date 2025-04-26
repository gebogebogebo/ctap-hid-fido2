use super::super::sub_command_base::SubCommandBase;
use super::bio_enrollment_params::TemplateInfo;
use crate::{ctapdef, encrypt::enc_hmac_sha_256, pintoken::PinToken, fidokey::common};
use crate::util_ciborium::ToValue;
use anyhow::Result;
use ciborium::value::Value;
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
            map.push((0x01.to_value(), 0x01.to_value()));
            
            // subCommand(0x02)
            let sub_cmd_id = sub_command.id()?;
            map.push((0x02.to_value(), sub_cmd_id.to_value()));

            // subCommandParams (0x03): Map containing following parameters
            let (sub_command_params, sub_command_params_cbor) = create_sub_command_params(&sub_command)?;
            if let Some(param) = &sub_command_params {
                map.push((0x03.to_value(), param.clone()));
            }

            if let Some(pin_token) = pin_token {
                // pinUvAuthProtocol(0x04)
                map.push((0x04.to_value(), 0x01.to_value()));

                // pinUvAuthParam (0x05)
                let pin_uv_auth_param = create_pin_auth_param(pin_token, sub_cmd_id, &sub_command_params_cbor);
                map.push((0x05.to_value(), pin_uv_auth_param.to_value()));
            }
        },
        None => {
            // getModality (0x06)
            map.push((0x06.to_value(), true.to_value()));
        }
    }

    // Generate command payload
    let command_byte = if use_pre_bio_enrollment {
        ctapdef::AUTHENTICATOR_BIO_ENROLLMENT_P
    } else {
        ctapdef::AUTHENTICATOR_BIO_ENROLLMENT
    };

    // Use common::to_payload for CBOR serialization
    common::to_payload(map, command_byte)
}

/// Create sub-command parameters and their serialized form
fn create_sub_command_params(sub_command: &SubCommand) -> Result<(Option<Value>, Vec<u8>)> {
    if !sub_command.has_param() {
        return Ok((None, Vec::new()));
    }
    
    let param = match sub_command {
        SubCommand::EnrollBegin(timeout_milliseconds) => {
            Some(create_timeout_param(None, *timeout_milliseconds))
        }
        SubCommand::EnrollCaptureNextSample(template_info, timeout_milliseconds) => {
            Some(create_timeout_param(Some(template_info), *timeout_milliseconds))
        }
        SubCommand::SetFriendlyName(template_info) | SubCommand::RemoveEnrollment(template_info) => {
            Some(create_template_info_param(template_info))
        }
        _ => None,
    };

    if let Some(param_val) = &param {
        // Serialize to bytes
        let mut cbor_data = Vec::new();
        ciborium::ser::into_writer(param_val, &mut cbor_data)?;
        Ok((param, cbor_data))
    } else {
        Ok((None, Vec::new()))
    }
}

/// Create PIN authentication parameter
fn create_pin_auth_param(pin_token: &PinToken, sub_cmd_id: u8, sub_command_params_cbor: &[u8]) -> Vec<u8> {
    let mut message = vec![0x01_u8];  // fingerprint modality
    message.push(sub_cmd_id);
    message.extend_from_slice(sub_command_params_cbor);
    let sig = enc_hmac_sha_256::authenticate(&pin_token.key, &message);
    sig[0..16].to_vec()
}

/// Create template info parameter
fn create_template_info_param(template_info: &TemplateInfo) -> Value {
    let mut param = Vec::new();
    param.push((0x01.to_value(), template_info.template_id.to_value()));
    
    if let Some(friendly_name) = &template_info.template_friendly_name {
        param.push((0x02.to_value(), friendly_name.to_value()));
    }
    
    param.to_value()
}

/// Create timeout parameter
fn create_timeout_param(
    template_info: Option<&TemplateInfo>,
    timeout_milliseconds: Option<u16>,
) -> Value {
    let mut param = Vec::new();
    
    if let Some(template_info) = template_info {
        param.push((0x01.to_value(), template_info.template_id.to_value()));
    }
    
    if let Some(timeout) = timeout_milliseconds {
        param.push((0x03.to_value(), timeout.to_value()));
    }
    
    param.to_value()
}
