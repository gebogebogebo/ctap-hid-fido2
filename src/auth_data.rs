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
            // bit[0]: User Present (UP)
            user_present_result: matches!(byte & 0x01, 0x01),

            // bit[1]: Reserved for future use (RFU1)

            // bit[2]: User Verified (UV)
            user_verified_result: matches!(byte & 0x04, 0x04),

            // bit[3]-[5]: 3-5: Reserved for future use (RFU2)

            // bit[6]: Attested credential data included (AT)
            // https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
            // For assertion signatures, the AT flag MUST NOT be set and the attestedCredentialData MUST NOT be included.
            attested_credential_data_included: matches!(byte & 0x40, 0x40),

            // bit[7]: Extension data included (ED)
            extension_data_included: matches!(byte & 0x80, 0x80),
        };
        Ok(flags)
    }

    pub fn as_u8(&self) -> u8 {
        let mut ret = 0x0;
        if self.user_present_result {
            ret |= 0x01;
        }
        if self.user_verified_result {
            ret |= 0x04;
        }
        if self.attested_credential_data_included {
            ret |= 0x40;
        }
        if self.extension_data_included {
            ret |= 0x80;
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
