use crate::ctapdef;

pub fn create_payload() -> Vec<u8> {
    // 6.9. authenticatorSelection (0x0B)
    vec![ctapdef::AUTHENTICATOR_SELECTION]
}
