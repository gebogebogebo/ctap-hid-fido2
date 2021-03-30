use crate::util;
use serde_cbor::Value;

#[derive(Debug, Default)]
pub struct CredsMetadata {
    pub existing_resident_credentials_count: u32,
    pub max_possible_remaining_resident_credentials_count: u32,
}
impl CredsMetadata {
    #[allow(dead_code)]
    pub fn print(self: &CredsMetadata, title: &str) {
        println!("{}", title);
        println!("- existing_resident_credentials_count               = {:?}", self.existing_resident_credentials_count);
        println!("- max_possible_remaining_resident_credentials_count = {:?}", self.max_possible_remaining_resident_credentials_count);
    }
}

pub fn parse_cbor(bytes: &[u8]) -> Result<CredsMetadata, String> {
    let mut data = CredsMetadata::default();

    let cbor = serde_cbor::from_slice(bytes).unwrap();
    if let Value::Map(n) = cbor {
        for (key, val) in &n {
            if let Value::Integer(member) = key {
                match member {
                    0x01 => data.existing_resident_credentials_count = util::cbor_cast_value(val).unwrap(),
                    0x02 => data.max_possible_remaining_resident_credentials_count = util::cbor_cast_value(val).unwrap(),
                    _ => println!("parse_cbor_member - unknown info {:?}", member),
                }
            }
        }
        Ok(data)
    } else {
        Err(String::from("parse error!"))
    }
}
