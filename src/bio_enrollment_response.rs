//use crate::credential_management_params;
use serde_cbor::Value;
#[allow(unused_imports)]
use crate::util;

pub(crate) fn parse_cbor(bytes: &[u8]) -> Result<(), String> {
    //let mut data = credential_management_params::CredentialManagementData::default();
    if bytes.len() == 0 {
        return Ok(());
    }

    let cbor = serde_cbor::from_slice(bytes).unwrap();
    if let Value::Map(n) = cbor {
        for (key, val) in &n {
            if let Value::Integer(member) = key {
                match member {
                    0x01 => {
                    }
                    0x02 => {
                    }
                    _ => println!("parse_cbor_member - unknown info {:?}", member),
                }
            }
        }
        Ok(())
    } else {
        Err(String::from("parse error!"))
    }
}
