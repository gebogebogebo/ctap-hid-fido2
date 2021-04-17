// Authenticator API
// CTAP 2.0
pub const AUTHENTICATOR_MAKE_CREDENTIAL: u8 = 0x01;
pub const AUTHENTICATOR_GET_ASSERTION: u8 = 0x02;
pub const AUTHENTICATOR_GET_INFO: u8 = 0x04;
pub const AUTHENTICATOR_CLIENT_PIN: u8 = 0x06;
// CTAP 2.1

pub const AUTHENTICATOR_BIO_ENROLLMENT: u8 = 0x40;
// 6.8. authenticatorCredentialManagement (0x0A)
//pub const AUTHENTICATOR_CREDENTIAL_MANAGEMENT: u8 = 0x0A;
// 6.13. Prototype authenticatorCredentialManagement (0x41) (For backwards compatibility with "FIDO_2_1_PRE" )
pub const AUTHENTICATOR_CREDENTIAL_MANAGEMENT: u8 = 0x41;
pub const AUTHENTICATOR_SELECTION: u8 = 0x0B;
pub const AUTHENTICATOR_CONFIG: u8 = 0x0D;
