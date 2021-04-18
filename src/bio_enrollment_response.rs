use crate::bio_enrollment_params;
#[allow(unused_imports)]
use crate::util;
use serde_cbor::Value;

pub(crate) fn parse_cbor(bytes: &[u8]) -> Result<(), String> {
    let mut data = bio_enrollment_params::BioEnrollmentData::default();
    let maps = util::cbor_bytes_to_map(bytes)?;
    for (key, val) in &maps {
        if let Value::Integer(member) = key {
            match member {
                0x01 => data.modality = util::cbor_value_to_num(val)?,
                0x02 => {}
                _ => println!("parse_cbor_member - unknown info {:?}", member),
            }
        }
    }
    Ok(())
}
