/*!
make_credential API parameters()
*/

/// Result of make_credential_with_pin_non_rk()
#[derive(Debug, Default)]
pub struct MakeCredentialWithPinNonRkResult {
    pub credential_id: Vec<u8>,    
}

#[derive(Debug, Default)]
pub struct MakeCredentialWithPinRkParams{
    pub user_id : Vec<u8>,
    pub user_name: String,
    pub user_display_name : String,
}