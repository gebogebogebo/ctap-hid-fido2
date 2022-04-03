use crate::{
    ctapdef,
    ctaphid,
};

use super::FidoKeyHid;

use anyhow::{Error, Result};
use serde_cbor::to_vec;
use serde_cbor::Value;
use std::collections::BTreeMap;

/// The subcommand for setting configurations on a hardware token. 
#[allow(dead_code)]
pub enum SubCommand {
    EnableEnterpriseAttestation = 0x01,
    ToggleAlwaysUv = 0x02,
    SetMinPinLength = 0x03,
    VendorPrototype = 0x04,
}

fn create_payload_enable_enterprise_attestation() -> Vec<u8> {
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


impl FidoKeyHid {
    /// Get Config (CTAP 2.1)
    pub fn config(&self) -> Result<String> {
        let cid = ctaphid::ctaphid_init(&self).map_err(Error::msg)?;
        let send_payload = create_payload_enable_enterprise_attestation();
        let _response_cbor = ctaphid::ctaphid_cbor(&self, &cid, &send_payload).map_err(Error::msg)?;
        Ok("".to_string())
    }
}

