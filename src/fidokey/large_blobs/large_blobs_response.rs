use super::large_blobs_params::LargeBlobData;
use crate::util_ciborium;
use anyhow::Result;

pub(crate) fn parse_cbor(bytes: &[u8]) -> Result<LargeBlobData> {
    let mut large_blobs_data = LargeBlobData::default();
    let maps = util_ciborium::cbor_bytes_to_map(bytes)?;
    for (key, val) in &maps {
        if util_ciborium::is_integer(key) {
            match util_ciborium::integer_to_i64(key)? {
                0x01 => {
                    // config -> Byte String
                    let data = util_ciborium::cbor_value_to_vec_u8(val)?;

                    // Split data into large_blob_array and hash
                    large_blobs_data.large_blob_array = data[0..(data.len() - 16)].to_vec();
                    large_blobs_data.hash = data[(data.len() - 16)..(data.len())].to_vec();
                }
                _ => println!("Unknown member: {}", util_ciborium::integer_to_i64(key)?),
            }
        }
    }

    Ok(large_blobs_data)
}
