use crate::util;

//#[derive(Default)]
pub(crate) struct StrBuf {
    buf: String,
}
impl StrBuf {
    pub(crate) fn new() -> StrBuf {
        StrBuf {buf:String::from("")}
    }

    pub(crate)fn append<T:std::fmt::Display>(&mut self,title:&str,val:&T) -> &mut Self{
        let tmp = format!("{} = {}\n",title,val);
        self.buf = self.buf.to_string() + &tmp;
        self
    }
    pub(crate)fn appenh(&mut self,title:&str,bytes:&[u8]) -> &mut Self{
        let tmp = format!("{}({:02}) = {}\n",title,bytes.len(),util::to_hex_str(bytes));
        self.buf = self.buf.to_string() + &tmp;
        self
    }

    pub(crate)fn build(&self) -> &str{
        &self.buf
    }
}

