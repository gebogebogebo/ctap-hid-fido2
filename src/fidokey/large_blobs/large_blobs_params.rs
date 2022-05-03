
#[derive(Debug, Default, Clone)]
pub struct LargeBlobData {
  pub large_blob_array: Vec<u8>,
  pub hash: Vec<u8>,
}
