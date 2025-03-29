use crate::ctapdef;
use crate::encrypt::cose;
use crate::fidokey::common;
use crate::util_ciborium;
use anyhow::{anyhow, Result};
use ciborium::value::Value;
use ciborium::cbor;

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
        cbor!(sub_command as i64).unwrap().into()
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
        Value::Integer((permission as i64).into())
    }
}

fn create_payload_get_uv_retries() -> Result<Vec<u8>> {
    let mut map = Vec::new();
    insert_pin_protocol(&mut map)?;
    insert_sub_command(&mut map, SubCommand::GetUVRetries)?;
    to_payload(map)
}

fn create_payload_get_retries() -> Result<Vec<u8>> {
    let mut map = Vec::new();
    insert_pin_protocol(&mut map)?;
    insert_sub_command(&mut map, SubCommand::GetRetries)?;
    to_payload(map)
}

fn create_payload_get_keyagreement() -> Result<Vec<u8>> {
    let mut map = Vec::new();
    insert_pin_protocol(&mut map)?;
    insert_sub_command(&mut map, SubCommand::GetKeyAgreement)?;
    to_payload(map)
}

pub fn create_payload_get_pin_token(key_agreement: &cose::CoseKey, pin_hash_enc: &[u8]) -> Result<Vec<u8>> {
    let mut map = Vec::new();
    insert_pin_protocol(&mut map)?;
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
    insert_pin_protocol(&mut map)?;
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
    insert_pin_protocol(&mut map)?;
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
    insert_pin_protocol(&mut map)?;
    insert_sub_command(
        &mut map,
        SubCommand::GetPinUvAuthTokenUsingPinWithPermissions,
    )?;
    insert_key_agreement(&mut map, key_agreement)?;

    // pinHashEnc(0x06) - Byte String
    let value = Value::Bytes(pin_hash_enc.to_vec());
    map.push((cbor!(0x06)?, value));

    // permission(0x09) - Unsigned Integer
    map.push((cbor!(0x09)?, permission.into()));

    to_payload(map)
}

pub fn create_payload_get_pin_uv_auth_token_using_uv_with_permissions(
    key_agreement: &cose::CoseKey,
    permission: Permission,
    rpid: &str,
) -> Result<Vec<u8>> {
    let mut map = Vec::new();
    insert_pin_protocol(&mut map)?;
    insert_sub_command(&mut map, SubCommand::GetPinUvAuthTokenUsingUvWithPermissions)?;
    insert_key_agreement(&mut map, key_agreement)?;

    // permission(0x09) - Unsigned Integer
    map.push((cbor!(0x09)?, permission.into()));

    // rpid(0x0A) - String
    map.push((cbor!(0x0A)?, cbor!(rpid)?));

    to_payload(map)
}

fn to_payload(map: Vec<(Value, Value)>) -> Result<Vec<u8>> {
    common::to_payload(map, ctapdef::AUTHENTICATOR_CLIENT_PIN)
}

// 0x01 : pin_protocol
fn insert_pin_protocol(map: &mut Vec<(Value, Value)>) -> Result<()> {
    let pin_protocol = cbor!(1)?;
    map.push((cbor!(0x01)?, pin_protocol));
    Ok(())
}

// 0x02 : sub_command
fn insert_sub_command(map: &mut Vec<(Value, Value)>, cmd: SubCommand) -> Result<()> {
    map.push((cbor!(0x02)?, cmd.into()));
    Ok(())
}

// 0x03 : key_agreement : COSE_Key
fn insert_key_agreement(map: &mut Vec<(Value, Value)>, key_agreement: &cose::CoseKey) -> Result<()> {
    let mut ka_val = Vec::new();
    ka_val.push((
        cbor!(1)?,
        cbor!(key_agreement.key_type)?,
    ));
    ka_val.push((
        cbor!(3)?,
        cbor!(key_agreement.algorithm)?,
    ));

    let param = key_agreement.parameters.get(&-1).unwrap().clone();
    if util_ciborium::is_integer(&param) {
        ka_val.push((cbor!(-1)?, cbor!(param)?));
    }

    let bval = key_agreement.parameters.get(&-2).unwrap().clone();
    if util_ciborium::is_bytes(&bval) {
        ka_val.push((cbor!(-2)?, cbor!(bval)?));
    }

    let bval = key_agreement.parameters.get(&-3).unwrap().clone();
    if util_ciborium::is_bytes(&bval) {
        ka_val.push((cbor!(-3)?, cbor!(bval)?));
    }
    
    let tmp = util_ciborium::vec_to_btree_map(ka_val)?;
    let ka = cbor!(tmp)?;

    map.push((cbor!(0x03)?, ka));
    Ok(())
}

// 0x04 : pin_auth
fn insert_pin_auth(map: &mut Vec<(Value, Value)>, pin_auth: &[u8]) -> Result<()> {
    let pin_auth_val = Value::Bytes(pin_auth.to_vec());
    map.push((cbor!(0x04)?, pin_auth_val));
    Ok(())
}

// 0x05 : new_pin_enc
fn insert_new_pin_enc(map: &mut Vec<(Value, Value)>, new_pin_enc: &[u8]) -> Result<()> {
    let new_pin_enc_val = Value::Bytes(new_pin_enc.to_vec());
    map.push((cbor!(0x05)?, new_pin_enc_val));
    Ok(())
}

// 0x06 : pin_hash_enc
fn insert_pin_hash_enc(map: &mut Vec<(Value, Value)>, pin_hash_enc: &[u8]) -> Result<()> {
    let pin_hash_enc_val = Value::Bytes(pin_hash_enc.to_vec());
    map.push((cbor!(0x06)?, pin_hash_enc_val));
    Ok(())
}

pub fn create_payload(sub_command: SubCommand) -> Result<Vec<u8>> {
    match sub_command {
        SubCommand::GetRetries => create_payload_get_retries(),
        SubCommand::GetKeyAgreement => create_payload_get_keyagreement(),
        SubCommand::SetPin => Err(anyhow!("Not Supported")),
        SubCommand::ChangePin => Err(anyhow!("Not Supported")),
        SubCommand::GetPinToken => Err(anyhow!("Not Supported")),
        SubCommand::GetPinUvAuthTokenUsingUvWithPermissions => Err(anyhow!("Not Supported")),
        SubCommand::GetUVRetries => create_payload_get_uv_retries(),
        SubCommand::GetPinUvAuthTokenUsingPinWithPermissions => Err(anyhow!("Not Supported")),
    }
}
