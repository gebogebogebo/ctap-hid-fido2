use crate::public_key::PublicKey;
use crate::public_key_credential_descriptor::PublicKeyCredentialDescriptor;
use crate::public_key_credential_rp_entity::PublicKeyCredentialRpEntity;
use crate::public_key_credential_user_entity::PublicKeyCredentialUserEntity;
use crate::util;
use std::fmt;

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

#[derive(Debug, Default, Clone)]
pub struct Credential {
    pub public_key_credential_user_entity: PublicKeyCredentialUserEntity,
    pub public_key_credential_descriptor: PublicKeyCredentialDescriptor,
    pub public_key: PublicKey,
}
impl Credential {
    pub(crate) fn new(meta: &CredentialManagementData) -> Credential {
        let mut ret = Credential::default();
        ret.public_key_credential_user_entity = meta.public_key_credential_user_entity.clone();
        ret.public_key_credential_descriptor = meta.public_key_credential_descriptor.clone();
        ret.public_key = meta.public_key.clone();
        ret
    }
}
impl fmt::Display for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tmp1 = "- public_key_credential_user_entity = ";
        let tmp2 = "- public_key_credential_descriptor  = ";
        let tmp3 = "- public_key                        = ";
        write!(
            f,
            "{}{}\n{}{}\n{}{}",
            tmp1,
            self.public_key_credential_user_entity,
            tmp2,
            self.public_key_credential_descriptor,
            tmp3,
            self.public_key
        )
    }
}
