use ctap_hid_fido2::{
  Cfg, FidoKeyHidFactory, verifier,
  fidokey::{GetAssertionArgsBuilder, MakeCredentialArgsBuilder},
};

fn main() {
    let rpid = "reg-auth-example-app";
    let pin = get_input_with_message("input PIN:");

    println!("Register");
    // create `challenge` (Correct implementation is done on the server side)
    let challenge = verifier::create_challenge();
    // create `MakeCredentialArgs`
    let make_credential_args = MakeCredentialArgsBuilder::new(rpid, &challenge)
        .pin(&pin)
        .build();
    // create `FidoKeyHid`
    let device = FidoKeyHidFactory::create(&Cfg::init()).unwrap();
    // get `Attestation` Object
    let attestation = device
        .make_credential_with_args(&make_credential_args)
        .unwrap();
    println!("- Register Success");
    // verify `Attestation` Object (Correct implementation is done on the server side)
    let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
    if !verify_result.is_success {
        println!("- ! Verify Failed");
        return;
    }
    // store Credential Id and Publickey (Correct implementation is done on the server side)
    let userdata_credential_id = verify_result.credential_id;
    let userdata_credential_publickey_der = verify_result.credential_publickey_der;

    println!("Authenticate");
    // create `challenge` (Correct implementation is done on the server side)
    let challenge = verifier::create_challenge();
    // create `GetAssertionArgs`
    let get_assertion_args = GetAssertionArgsBuilder::new(rpid, &challenge)
        .pin(&pin)
        .credential_id(&userdata_credential_id)
        .build();
    // get `Assertion` Object (Correct implementation is done on the server side)
    let assertions = device.get_assertion_with_args(&get_assertion_args).unwrap();
    println!("- Authenticate Success");
    // verify `Assertion` Object
    if !verifier::verify_assertion(
        rpid,
        &userdata_credential_publickey_der,
        &challenge,
        &assertions[0],
    ) {
        println!("- ! Verify Assertion Failed");
    }
}

pub fn get_input() -> String {
    let mut word = String::new();
    std::io::stdin().read_line(&mut word).ok();
    return word.trim().to_string();
}

pub fn get_input_with_message(message: &str) -> String {
    println!("{}", message);
    let input = get_input();
    println!();
    input
}
