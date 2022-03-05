use crate::str_buf::StrBuf;
use anyhow::Result;
use std::fmt;

#[derive(Debug, Default, Clone)]
pub struct Flags {
    pub user_present_result: bool,
    pub user_verified_result: bool,
    pub attested_credential_data_included: bool,
    pub extension_data_included: bool,
}

impl Flags {
    pub(crate) fn parse(byte: u8) -> Result<Flags> {
        let flags = Flags {
            user_present_result: matches!(byte & 0x01, 0x01),
            user_verified_result: matches!(byte & 0x04, 0x04),
            attested_credential_data_included: matches!(byte & 0x40, 0x40),
            extension_data_included: matches!(byte & 0x80, 0x80),
        };
        Ok(flags)
    }

    pub fn as_u8(&self) -> u8 {
        let mut ret = 0x0;
        if self.user_present_result {
            ret = ret | 0x01;
        }
        if self.user_verified_result {
            ret = ret | 0x04;
        }
        if self.attested_credential_data_included {
            ret = ret | 0x40;
        }
        if self.extension_data_included {
            ret = ret | 0x80;
        }

        ret
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut strbuf = StrBuf::new(42);
        strbuf
            .append("- user_present_result", &self.user_present_result)
            .append("- user_verified_result", &self.user_verified_result)
            .append(
                "- attested_credential_data_included",
                &self.attested_credential_data_included,
            )
            .append("- extension_data_included", &self.extension_data_included);
        write!(f, "{}", strbuf.build())
    }
}
