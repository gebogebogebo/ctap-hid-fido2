/*!
get_assertion API parameters()
*/

/// Result of get_assertion_with_pin()
#[derive(Debug, Default)]
pub struct GetAssertionWithPinResult {
    pub number_of_credentials: i32,
}

/// Assertion Object
#[derive(Debug, Default)]
pub struct Assertion {
    pub rpid_hash: Vec<u8>,
    pub flags_user_present_result: bool,
    pub flags_user_verified_result: bool,
    pub flags_attested_credential_data_included: bool,
    pub flags_extension_data_included: bool,

    pub sign_count: u32,
    pub aaguid: Vec<u8>,

    pub number_of_credentials: i32,

    pub signature: Vec<u8>,
    pub user_id: Vec<u8>,
    pub user_name: String,
    pub user_display_name: String,

    pub credential_id: Vec<u8>,
}
