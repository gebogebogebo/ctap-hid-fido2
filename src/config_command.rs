
use crate::ctapdef;
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;

#[allow(dead_code)]
pub enum SubCommand {
    EnableEnterpriseAttestation = 0x01,
    ToggleAlwaysUv = 0x02,
    SetMinPINLength = 0x03,
    VendorPrototype = 0x04,
}

pub fn create_payload_enable_enterprise_attestation() -> Vec<u8> {
    // 0x01 : subCommand
    let sub_cmd = Value::Integer(SubCommand::EnableEnterpriseAttestation as i128);

    // create cbor
    let mut map = BTreeMap::new();
    map.insert(Value::Integer(0x01), sub_cmd);
    let cbor = Value::Map(map);

    let mut payload = [ctapdef::AUTHENTICATOR_CONFIG].to_vec();
    payload.append(&mut to_vec(&cbor).unwrap());
    payload
}
