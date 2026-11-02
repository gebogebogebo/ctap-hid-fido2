use super::large_blobs_params::LargeBlobData;
use crate::util_ciborium;
use anyhow::{anyhow, Result};

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
                    let split = data.len().checked_sub(16).ok_or_else(|| {
                        anyhow!("large blob data too short: {} bytes", data.len())
                    })?;
                    let (large_blob_array, hash) = data.split_at(split);
                    large_blobs_data.large_blob_array = large_blob_array.to_vec();
                    large_blobs_data.hash = hash.to_vec();
                }
                _ => println!("Unknown member: {}", util_ciborium::integer_to_i64(key)?),
            }
        }
    }

    Ok(large_blobs_data)
}

#[cfg(test)]
mod tests {
    use super::parse_cbor;

    #[test]
    fn test_parse_cbor_splits_array_and_hash() {
        // {1: h'80' || LEFT(SHA-256(h'80'), 16)} -- the initial empty largeBlobArray
        let bytes = hex::decode("A101518076BE8B528D0075F7AAE98D6FA57A6D3C").unwrap();
        let data = parse_cbor(&bytes).unwrap();
        assert_eq!(data.large_blob_array, vec![0x80]);
        assert_eq!(hex::encode(&data.hash), "76be8b528d0075f7aae98d6fa57a6d3c");
    }

    #[test]
    fn test_parse_cbor_rejects_data_shorter_than_hash() {
        // {1: h'00'} -- shorter than the 16-byte trailing hash
        let bytes = hex::decode("A1014100").unwrap();
        assert!(parse_cbor(&bytes).is_err());
    }
}
