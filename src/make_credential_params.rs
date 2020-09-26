/*!
make_credential API parameters()
*/

#[derive(Debug, Default)]
pub struct RkParam {
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,
}

/// Attestation Object
/// https://www.w3.org/TR/webauthn/#sctn-attestation
#[derive(Debug, Default)]
pub struct Attestation {
    pub fmt: String,
    pub rpid_hash: Vec<u8>,
    pub flags_user_present_result: bool,
    pub flags_user_verified_result: bool,
    pub flags_attested_credential_data_included: bool,
    pub flags_extension_data_included: bool,
    pub sign_count: u32,
    pub aaguid: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub credential_publickey: String,
    pub credential_publickey_byte: Vec<u8>,
    pub authdata: Vec<u8>,

    pub attstmt_alg: u32,
    pub attstmt_sig: Vec<u8>,
    pub attstmt_x5c: Vec<u8>,
}
