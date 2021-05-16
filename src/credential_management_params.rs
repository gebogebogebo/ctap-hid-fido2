use crate::public_key::PublicKey;
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use crate::public_key_credential_rp_entity::PublicKeyCredentialRpEntity;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::util;
use std::fmt;
use crate::str_buf::StrBuf;

#[derive(Debug, Default, Clone)]
pub(crate) struct CredentialManagementData {
    pub existing_resident_credentials_count: u32,
    pub max_possible_remaining_resident_credentials_count: u32,
    pub public_key_credential_rp_entity: PublicKeyCredentialRpEntity,
    pub rpid_hash: Vec<u8>,
    pub total_rps: u32,
    pub public_key_credential_user_entity: PublicKeyCredentialUserEntity,
    pub public_key_credential_descriptor: PublicKeyCredentialDescriptor,
    pub public_key: PublicKey,
    pub total_credentials: u32,
    pub cred_protect: u32,
    pub large_blob_key: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct CredentialsCount {
    pub existing_resident_credentials_count: u32,
    pub max_possible_remaining_resident_credentials_count: u32,
}
impl CredentialsCount {
    pub(crate) fn new(meta: &CredentialManagementData) -> CredentialsCount {
        let mut ret = CredentialsCount::default();
        ret.existing_resident_credentials_count = meta.existing_resident_credentials_count;
        ret.max_possible_remaining_resident_credentials_count =
            meta.max_possible_remaining_resident_credentials_count;
        ret
    }
}
impl fmt::Display for CredentialsCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "- existing_resident_credentials_count = {}\n- max_possible_remaining_resident_credentials_count = {}", self.existing_resident_credentials_count, self.max_possible_remaining_resident_credentials_count)
    }
}

#[derive(Debug, Default, Clone)]
pub struct Rp {
    pub public_key_credential_rp_entity: PublicKeyCredentialRpEntity,
    pub rpid_hash: Vec<u8>,
}
impl Rp {
    pub(crate) fn new(meta: &CredentialManagementData) -> Rp {
        let mut ret = Rp::default();
        ret.public_key_credential_rp_entity = meta.public_key_credential_rp_entity.clone();
        ret.rpid_hash = meta.rpid_hash.to_vec();
        ret
    }
}
impl fmt::Display for Rp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tmp1 = format!("- public_key_credential_rp_entity = ");
        let tmp2 = format!(
            "- rpid_hash({:02})                   = ",
            self.rpid_hash.len()
        );
        write!(
            f,
            "{}{}\n{}{}",
            tmp1,
            self.public_key_credential_rp_entity,
            tmp2,
            util::to_hex_str(&self.rpid_hash)
        )
    }
}

#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum CredentialProtectionPolicy {
    Unknown,
    UserVerificationOptional,
    UserVerificationOptionalWithCredentialIDList,
    UserVerificationRequired,
}
impl Default for CredentialProtectionPolicy {
    fn default() -> Self {
        CredentialProtectionPolicy::Unknown
    }
}
impl From<u32> for CredentialProtectionPolicy {
    fn from(from: u32) -> CredentialProtectionPolicy {
        match from {
            0x01 => CredentialProtectionPolicy::UserVerificationOptional,
            0x02 => CredentialProtectionPolicy::UserVerificationOptionalWithCredentialIDList,
            0x03 => CredentialProtectionPolicy::UserVerificationRequired,
            _ => CredentialProtectionPolicy::Unknown,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct Credential {
    pub public_key_credential_user_entity: PublicKeyCredentialUserEntity,
    pub public_key_credential_descriptor: PublicKeyCredentialDescriptor,
    pub public_key: PublicKey,
    pub cred_protect: CredentialProtectionPolicy,
}
impl Credential {
    pub(crate) fn new(d: &CredentialManagementData) -> Credential {
        Credential {
            public_key_credential_user_entity: d.public_key_credential_user_entity.clone(),
            public_key_credential_descriptor: d.public_key_credential_descriptor.clone(),
            public_key: d.public_key.clone(), cred_protect: d.cred_protect.into()
        }
    }
}
impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut strbuf = StrBuf::new(42);
        strbuf
            .append("- public_key_credential_user_entity", &self.public_key_credential_user_entity)
            .append("- public_key_credential_descriptor", &self.public_key_credential_descriptor)
            .append("- public_key",&self.public_key)
            .append("- cred_protect", &format!("{:?}",self.cred_protect));
        write!(f, "{}", strbuf.build())
    }
}
