use anyhow::{Error, Result};
use crate::util;
use serde_cbor::Value;

pub(crate) fn parse_cbor(bytes: &[u8]) -> Result<()> {
  let maps = util::cbor_bytes_to_map(bytes).map_err(Error::msg)?;
  for (key, val) in &maps {
      if let Value::Integer(member) = key {
          match member {
              0x01 => {
                // config -> Byte String
                let data = util::cbor_value_to_vec_u8(val).map_err(Error::msg)?;
                // TODO for Debug
                println!("{:?}",util::to_hex_str(&data));
              }
             _ => println!("parse_cbor_member - unknown member {:?}", member),
          }
      }
  }

  Ok(())
}