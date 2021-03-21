use crate::ctapdef;

pub fn create_payload() -> Vec<u8> {
    // Command Value - authenticatorGetInfo (0x04)
    vec![ctapdef::AUTHENTICATOR_GET_INFO]
}
