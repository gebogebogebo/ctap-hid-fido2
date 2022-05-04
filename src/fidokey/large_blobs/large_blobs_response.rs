use super::large_blobs_params::LargeBlobData;
use crate::util;
use anyhow::{Error, Result};
use serde_cbor::Value;

pub(crate) fn parse_cbor(bytes: &[u8]) -> Result<LargeBlobData> {
    let mut large_blobs_data = LargeBlobData::default();
    let maps = util::cbor_bytes_to_map(bytes).map_err(Error::msg)?;
    for (key, val) in &maps {
        if let Value::Integer(member) = key {
            match member {
                0x01 => {
                    // config -> Byte String
                    let data = util::cbor_value_to_vec_u8(val).map_err(Error::msg)?;
                    // TODO for Debug
                    //println!("{:?}", util::to_hex_str(&data));

                    large_blobs_data.large_blob_array = data[0..(data.len() - 16)].to_vec();
                    large_blobs_data.hash = data[(data.len() - 16)..(data.len())].to_vec();
                    // TODO for Debug
                    // println!(
                    //     "- {:?}",
                    //     util::to_hex_str(&large_blobs_data.large_blob_array)
                    // );
                    // println!("- {:?}", util::to_hex_str(&large_blobs_data.hash));
                }
                _ => println!("parse_cbor_member - unknown member {:?}", member),
            }
        }
    }

    Ok(large_blobs_data)
}
