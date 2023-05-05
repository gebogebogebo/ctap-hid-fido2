use crate::fidokey::get_assertion::get_assertion_params;
use crate::fidokey::make_credential::make_credential_params;
use crate::util;
use crate::public_key::{PublicKey, PublicKeyType};
use ring::digest;
use ring::rand::SecureRandom;
use ring::signature;
use x509_parser::prelude::*;

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
    pub credential_public_key: PublicKey,
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

    let public_key_der = {
        let res = X509Certificate::from_der(&attestation.attstmt_x5c[0]);
        let cert = {
            match res {
                Ok((_rem, cert)) => {
                    //assert!(rem.is_empty());
                    //assert_eq!(cert.tbs_certificate.version, X509Version::V3);
                    cert
                }
                _ => panic!("x509 parsing failed: {:?}", res),
            }
        };
        cert.tbs_certificate.subject_pki.subject_public_key
    };

    // TODO Ecdsa256 fixed
    let public_key = PublicKey::with_der(public_key_der.as_ref(), PublicKeyType::Ecdsa256);

    // Verify the signature.
    let result = verify_sig(
        &public_key,
        challenge,
        &attestation.auth_data,
        &attestation.attstmt_sig,
    );

    AttestationVerifyResult {
        is_success: result,
        credential_id: attestation.credential_descriptor.id.to_vec(),
        credential_public_key: attestation.credential_publickey.clone(),
    }
}

/// Verify Assertion Object
pub fn verify_assertion(
    rpid: &str,
    publickey: &PublicKey,
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

fn verify_sig(public_key: &PublicKey, challenge: &[u8], auth_data: &[u8], sig: &[u8]) -> bool {
    // message = authData + SHA256(challenge)
    let message = {
        let mut base: Vec<u8> = vec![];
        base.append(&mut auth_data.to_vec());

        let cdh = digest::digest(&digest::SHA256, challenge);
        base.append(&mut cdh.as_ref().to_vec());
        base
    };

    let peer_public_key = match public_key.key_type {
        PublicKeyType::Ecdsa256 => signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key.der.to_vec()),
        PublicKeyType::Ed25519 => signature::UnparsedPublicKey::new(&signature::ED25519, public_key.der.to_vec()),
        _ => return false
    };

    let result = peer_public_key.verify(&message, sig);

    // log
    //print_verify_info(public_key_der, &message, sig, &result);

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

#[allow(dead_code)]
fn print_verify_info(
    public_key_der: &[u8],
    message: &[u8],
    sig: &[u8],
    verify_result: &Result<(), ring::error::Unspecified>,
) {
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
