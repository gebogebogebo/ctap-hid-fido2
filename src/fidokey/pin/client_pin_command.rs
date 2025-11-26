use crate::ctapdef;
use crate::encrypt::cose;
use crate::fidokey::common;
use crate::util_ciborium;
use crate::util_ciborium::ToValue;
use anyhow::{anyhow, Result};
use ciborium::value::Value;

#[allow(dead_code)]
pub enum SubCommand {
    GetRetries = 0x01,
    GetKeyAgreement = 0x02,
    SetPin = 0x03,
    ChangePin = 0x04,
    GetPinToken = 0x05,
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    GetUVRetries = 0x07,
    GetPinUvAuthTokenUsingPinWithPermissions = 0x09,
}
impl From<SubCommand> for Value {
    fn from(sub_command: SubCommand) -> Self {
        (sub_command as i64).to_value()
    }
}

#[allow(dead_code)]
pub enum Permission {
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    CredentialManagement = 0x04,
    BioEnrollment = 0x08,
    LargeBlobWrite = 0x10,
    AuthenticatorConfiguration = 0x20,
}

impl From<Permission> for Value {
    fn from(permission: Permission) -> Self {
        (permission as i64).to_value()
    }
}

fn create_payload_get_uv_retries(pin_protocol_version: u8) -> Result<Vec<u8>> {
    let mut map = Vec::new();
    insert_pin_protocol(&mut map, pin_protocol_version)?;
    insert_sub_command(&mut map, SubCommand::GetUVRetries)?;
    to_payload(map)
}

fn create_payload_get_retries(pin_protocol_version: u8) -> Result<Vec<u8>> {
    let mut map = Vec::new();
    insert_pin_protocol(&mut map, pin_protocol_version)?;
    insert_sub_command(&mut map, SubCommand::GetRetries)?;
    to_payload(map)
}

fn create_payload_get_keyagreement(pin_protocol_version: u8) -> Result<Vec<u8>> {
    let mut map = Vec::new();
    insert_pin_protocol(&mut map, pin_protocol_version)?;
    insert_sub_command(&mut map, SubCommand::GetKeyAgreement)?;
    to_payload(map)
}

pub fn create_payload_get_pin_token(key_agreement: &cose::CoseKey, pin_hash_enc: &[u8], pin_protocol_version: u8) -> Result<Vec<u8>> {
    let mut map = Vec::new();
    insert_pin_protocol(&mut map, pin_protocol_version)?;
    insert_sub_command(&mut map, SubCommand::GetPinToken)?;
    insert_key_agreement(&mut map, key_agreement)?;
    insert_pin_hash_enc(&mut map, pin_hash_enc)?;
    to_payload(map)
}

pub fn create_payload_set_pin(
    key_agreement: &cose::CoseKey,
    pin_auth: &[u8],
    new_pin_enc: &[u8],
) -> Result<Vec<u8>> {
    let mut map = Vec::new();
    insert_pin_protocol(&mut map, 1)?;
    insert_sub_command(&mut map, SubCommand::SetPin)?;
    insert_key_agreement(&mut map, key_agreement)?;
    insert_pin_auth(&mut map, pin_auth)?;
    insert_new_pin_enc(&mut map, new_pin_enc)?;
    to_payload(map)
}

pub fn create_payload_change_pin(
    key_agreement: &cose::CoseKey,
    pin_auth: &[u8],
    new_pin_enc: &[u8],
    pin_hash_enc: &[u8],
) -> Result<Vec<u8>> {
    let mut map = Vec::new();
    insert_pin_protocol(&mut map, 1)?;
    insert_sub_command(&mut map, SubCommand::ChangePin)?;
    insert_key_agreement(&mut map, key_agreement)?;
    insert_pin_auth(&mut map, pin_auth)?;
    insert_new_pin_enc(&mut map, new_pin_enc)?;
    insert_pin_hash_enc(&mut map, pin_hash_enc)?;
    to_payload(map)
}

pub fn create_payload_get_pin_uv_auth_token_using_pin_with_permissions(
    key_agreement: &cose::CoseKey,
    pin_hash_enc: &[u8],
    permission: Permission,
) -> Result<Vec<u8>> {
    let mut map = Vec::new();
    insert_pin_protocol(&mut map, 1)?;      // TODO
    insert_sub_command(
        &mut map,
        SubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
    )?;
    insert_key_agreement(&mut map, key_agreement)?;

    // pinHashEnc(0x06) - Byte String
    map.push((0x06.to_value(), pin_hash_enc.to_vec().to_value()));

    // permission(0x09) - Unsigned Integer
    map.push((0x09.to_value(), permission.into()));

    to_payload(map)
}

pub fn create_payload_get_pin_uv_auth_token_using_uv_with_permissions(
    key_agreement: &cose::CoseKey,
    permission: Permission,
    rpid: &str,
) -> Result<Vec<u8>> {
    let mut map = Vec::new();
    insert_pin_protocol(&mut map, 1)?;
    insert_sub_command(&mut map, SubCommand::GetPinUvAuthTokenUsingUvWithPermissions)?;
    insert_key_agreement(&mut map, key_agreement)?;

    // permission(0x09) - Unsigned Integer
    map.push((0x09.to_value(), permission.into()));

    // rpid(0x0A) - String
    map.push((0x0A.to_value(), rpid.to_value()));

    to_payload(map)
}

fn to_payload(map: Vec<(Value, Value)>) -> Result<Vec<u8>> {
    common::to_payload(map, ctapdef::AUTHENTICATOR_CLIENT_PIN)
}

// 0x01 : pin_protocol
fn insert_pin_protocol(
    map: &mut Vec<(Value, Value)>,
    pin_protocol_version: u8,
) -> Result<()> {
    map.push((0x01.to_value(), pin_protocol_version.to_value()));
    Ok(())
}

// 0x02 : sub_command
fn insert_sub_command(map: &mut Vec<(Value, Value)>, cmd: SubCommand) -> Result<()> {
    map.push((0x02.to_value(), cmd.into()));
    Ok(())
}

// 0x03 : key_agreement : COSE_Key
fn insert_key_agreement(map: &mut Vec<(Value, Value)>, key_agreement: &cose::CoseKey) -> Result<()> {
    let mut ka_val = Vec::new();
    ka_val.push((
        1.to_value(),
        key_agreement.key_type.to_value(),
    ));
    ka_val.push((
        3.to_value(),
        key_agreement.algorithm.to_value(),
    ));

    let param = key_agreement.parameters.get(&-1).unwrap().clone();
    if util_ciborium::is_integer(&param) {
        if let Ok(val) = util_ciborium::integer_to_i64(&param) {
            ka_val.push(((-1).to_value(), val.to_value()));
        }
    }

    let bval = key_agreement.parameters.get(&-2).unwrap().clone();
    if util_ciborium::is_bytes(&bval) {
        if let Ok(val) = util_ciborium::cbor_value_to_vec_u8(&bval) {
            ka_val.push(((-2).to_value(), val.to_value()));
        }
    }

    let bval = key_agreement.parameters.get(&-3).unwrap().clone();
    if util_ciborium::is_bytes(&bval) {
        if let Ok(val) = util_ciborium::cbor_value_to_vec_u8(&bval) {
            ka_val.push(((-3).to_value(), val.to_value()));
        }
    }
    
    // Create the CBOR map value directly
    let ka = ka_val.to_value();
    map.push((0x03.to_value(), ka));
    Ok(())
}

// 0x04 : pin_auth
fn insert_pin_auth(map: &mut Vec<(Value, Value)>, pin_auth: &[u8]) -> Result<()> {
    map.push((0x04.to_value(), pin_auth.to_vec().to_value()));
    Ok(())
}

// 0x05 : new_pin_enc
fn insert_new_pin_enc(map: &mut Vec<(Value, Value)>, new_pin_enc: &[u8]) -> Result<()> {
    map.push((0x05.to_value(), new_pin_enc.to_vec().to_value()));
    Ok(())
}

// 0x06 : pin_hash_enc
fn insert_pin_hash_enc(map: &mut Vec<(Value, Value)>, pin_hash_enc: &[u8]) -> Result<()> {
    map.push((0x06.to_value(), pin_hash_enc.to_vec().to_value()));
    Ok(())
}

pub fn create_payload(sub_command: SubCommand, pin_protocol_version: u8) -> Result<Vec<u8>> {
    match sub_command {
        SubCommand::GetRetries => create_payload_get_retries(pin_protocol_version),
        SubCommand::GetKeyAgreement => create_payload_get_keyagreement(pin_protocol_version),
        SubCommand::SetPin => Err(anyhow!("Not Supported")),
        SubCommand::ChangePin => Err(anyhow!("Not Supported")),
        SubCommand::GetPinToken => Err(anyhow!("Not Supported")),
        SubCommand::GetPinUvAuthTokenUsingUvWithPermissions => Err(anyhow!("Not Supported")),
        SubCommand::GetUVRetries => create_payload_get_uv_retries(pin_protocol_version),
        SubCommand::GetPinUvAuthTokenUsingPinWithPermissions => Err(anyhow!("Not Supported")),
    }
}
