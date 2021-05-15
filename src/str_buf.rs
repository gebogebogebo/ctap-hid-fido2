use crate::util;
use std::fmt::Display;

//#[derive(Default)]
pub struct StrBuf {
    buf: String,
}
impl StrBuf {
    pub fn new() -> Self {
        StrBuf {
            buf: String::from(""),
        }
    }

    pub fn append<T: Display>(&mut self, title: &str, val: &T) -> &mut Self {
        let tmp = format!("{} = {}\n", title, val);
        self.buf = self.buf.to_string() + &tmp;
        self
    }
    pub fn appenh(&mut self, title: &str, bytes: &[u8]) -> &mut Self {
        let tmp = format!(
            "{}({:02}) = {}\n",
            title,
            bytes.len(),
            util::to_hex_str(bytes)
        );
        self.buf = self.buf.to_string() + &tmp;
        self
    }

    pub fn build(&self) -> &str {
        &self.buf
    }
}
