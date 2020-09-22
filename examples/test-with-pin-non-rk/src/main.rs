extern crate ctap_hid_fido2;

fn main() {
    // parameter
    let rpid = "test.com";
    let challenge = b"this is challenge".to_vec();
    let user_id = b"12345".to_vec();
    let user_name = "test user";
    let pin = "1234";

    ctap_hid_fido2::make_credential_with_pin_non_rk(rpid,&challenge,&user_id,user_name,pin);
}
