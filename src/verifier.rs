/*!
Verify Attestation Assertion API
*/

use crate::get_assertion_params;
use crate::make_credential_params;
use crate::util;
use ring::digest;
use ring::rand::SecureRandom;
use ring::signature;
use x509_parser::parse_x509_der;

// Create Random Data
pub fn create_challenge() -> [u8; 32] {
    let rnd = ring::rand::SystemRandom::new();
    let mut tmp = [0; 32];
    rnd.fill(&mut tmp).unwrap();
    tmp
}

/// Attestation Verify Result
#[derive(Debug, Default)]
pub struct AttestationVerifyResult {
    pub is_success: bool,
    pub credential_id: Vec<u8>,
    pub credential_publickey_pem: String,
    pub credential_publickey_der: Vec<u8>,
}

/// Verify Atterstaion Object
pub fn verify_attestation(
    rpid: &str,
    challenge: &[u8],
    attestation: &make_credential_params::Attestation,
) -> AttestationVerifyResult {
    if !verify_rpid(rpid, &attestation.rpid_hash) {
        return AttestationVerifyResult::default();
    }

    let public_key = {
        let res = parse_x509_der(&attestation.attstmt_x5c[0]);
        let cert = {
            match res {
                Ok((rem, cert)) => {
                    assert!(rem.is_empty());
                    //
                    assert_eq!(cert.tbs_certificate.version, 2);
                    cert
                }
                _ => panic!("x509 parsing failed: {:?}", res),
            }
        };
        cert.tbs_certificate.subject_pki.subject_public_key
    };

    // Verify the signature.
    let result = verify_sig(
        public_key.as_ref(),
        challenge,
        &attestation.auth_data,
        &attestation.attstmt_sig,
    );

    AttestationVerifyResult {
        is_success: result,
        credential_id: attestation.credential_descriptor.id.to_vec(),
        credential_publickey_pem: attestation.credential_publickey.pem.to_string(),
        credential_publickey_der: attestation.credential_publickey.der.to_vec(),
    }
}

/// Verify Assertion Object
pub fn verify_assertion(
    rpid: &str,
    publickey: &[u8],
    challenge: &[u8],
    assertion: &get_assertion_params::Assertion,
) -> bool {
    // Verify rpid
    if !verify_rpid(rpid, &assertion.rpid_hash) {
        return false;
    }

    // Verify the signature.
    verify_sig(
        publickey,
        challenge,
        &assertion.auth_data,
        &assertion.signature,
    )
}

fn verify_sig(public_key_der: &[u8], challenge: &[u8], auth_data: &[u8], sig: &[u8]) -> bool {
    // public key
    let public_key_der = untrusted::Input::from(public_key_der);

    // message = authData + SHA256(challenge)
    let message = {
        let mut base: Vec<u8> = vec![];
        base.append(&mut auth_data.to_vec());

        let cdh = digest::digest(&digest::SHA256, challenge);
        base.append(&mut cdh.as_ref().to_vec());
        base
    };
    let message = untrusted::Input::from(&message);

    // sig
    let sig = untrusted::Input::from(&sig);

    // verify
    let result = signature::verify(
        &signature::ECDSA_P256_SHA256_ASN1,
        public_key_der,
        message,
        sig,
    );

    // log
    print_verify_info(
        public_key_der.as_slice_less_safe(),
        message.as_slice_less_safe(),
        sig.as_slice_less_safe(),
        &result,
    );

    match result {
        Ok(()) => true,
        Err(ring::error::Unspecified) => false,
    }
}

fn verify_rpid(rpid: &str, rpid_hash: &[u8]) -> bool {
    // SHA-256(rpid) == attestation.RpIdHash
    let rpid_hash_comp = {
        let hash = digest::digest(&digest::SHA256, rpid.as_bytes());
        util::to_hex_str(hash.as_ref())
    };

    rpid_hash_comp == util::to_hex_str(rpid_hash)
}

fn print_verify_info(
    public_key_der: &[u8],
    message: &[u8],
    sig: &[u8],
    verify_result: &Result<(), ring::error::Unspecified>,
) {
    if !util::is_debug() {
        return;
    }

    let public_key_pem = util::convert_to_publickey_pem(public_key_der);

    println!("-----------------------------");
    println!("Verify");
    println!(
        "- public_key_der({:02})  = {:?}",
        public_key_der.len(),
        util::to_hex_str(public_key_der)
    );
    println!(
        "- public_key_pem({:02})  = {:?}",
        public_key_pem.len(),
        public_key_pem
    );
    println!(
        "- message({:02})  = {:?}",
        message.len(),
        util::to_hex_str(message)
    );
    println!("- sig({:02})  = {:?}", sig.len(), util::to_hex_str(sig));
    println!("- verify result = {:?}", verify_result);
    println!("-----------------------------");
}
