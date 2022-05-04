use std::fmt;
use crate::str_buf::StrBuf;

#[derive(Debug, Default, Clone)]
pub struct LargeBlobData {
    pub large_blob_array: Vec<u8>,
    pub hash: Vec<u8>,
}

impl fmt::Display for LargeBlobData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut strbuf = StrBuf::new(33);
        strbuf.appenh("- large_blob_array", &self.large_blob_array);
        strbuf.appenh("- rpid_hash", &self.hash);
        write!(f, "{}", strbuf.build())
    }
}
