use crate::util;
use pad::PadStr;
use std::fmt::Display;

pub struct StrBuf {
    buf: String,
    pad: usize,
}
impl StrBuf {
    pub fn new(pad_to_width: usize) -> Self {
        StrBuf {
            buf: String::from(""),
            pad: pad_to_width,
        }
    }

    // add str and return StrBuf
    pub fn add(&mut self, val: &str) -> &mut Self {
        self.buf = self.buf.to_string() + val;
        self
    }

    // add str + ¥n and return StrBuf
    pub fn addln(&mut self, val: &str) -> &mut Self {
        self.buf = format!("{}{}\n", self.buf, val);
        self
    }

    // create String from title and bytes
    pub fn bufh(title: &str, bytes: &[u8]) -> String {
        let mut strbuf = StrBuf::new(0);
        strbuf.appenh(title, bytes).build().to_string()
    }

    pub fn appent(&mut self, title: &str) -> &mut Self {
        let tmp = format!("{}\n", title);
        self.buf = self.buf.to_string() + &tmp;
        self
    }

    pub fn append<T: Display>(&mut self, title: &str, val: &T) -> &mut Self {
        let tmp = format!("{} = {}\n", title.pad_to_width(self.pad), val);
        self.buf = self.buf.to_string() + &tmp;
        self
    }
    pub fn appenh(&mut self, title: &str, bytes: &[u8]) -> &mut Self {
        let title2 = format!("{}({:02})", title, bytes.len());
        let tmp = format!(
            "{} = {}\n",
            title2.pad_to_width(self.pad),
            util::to_hex_str(bytes)
        );
        self.buf = self.buf.to_string() + &tmp;
        self
    }

    pub fn build(&self) -> &str {
        &self.buf
    }
}
