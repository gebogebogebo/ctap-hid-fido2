use crate::make_credential_params;
use crate::util;
use ring::digest;
use ring::signature;
use x509_parser::parse_x509_der;

#[derive(Debug, Default)]
pub struct AttestationVerifyResult {
    pub is_verify:bool,
    pub credential_id: Vec<u8>,
    pub credential_publickey: Vec<u8>,
}

pub fn verify_attestation(
    rpid: &str,
    challenge: &[u8],
    attestation: &make_credential_params::Attestation,
) -> AttestationVerifyResult{
    if verify_rpid(rpid, &attestation.rpid_hash) == false {
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
    let public_key_der = untrusted::Input::from(public_key.as_ref());

    let result = verify_sig(
        &public_key_der,
        challenge,
        &attestation.authdata,
        &attestation.attstmt_sig,
    );

    let mut att_result = AttestationVerifyResult::default();
    att_result.is_verify = result;
    att_result.credential_id = attestation.credential_id.to_vec();
    att_result.credential_publickey = attestation.credential_publickey_byte.to_vec();
    att_result
}

fn verify_sig(public_key_der: &untrusted::Input, challenge: &[u8], auth_data: &[u8], sig: &[u8]) -> bool{
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

    /*
    println!("Verify");
    println!(
        "- public_key_der({:02})  = {:?}",
        public_key_der.len(),
        util::to_hex_str(public_key_der.as_slice_less_safe())
    );
    println!(
        "- challenge({:02})  = {:?}",
        challenge.len(),
        util::to_hex_str(challenge)
    );
    println!(
        "- authdata({:02})  = {:?}",
        auth_data.len(),
        util::to_hex_str(auth_data)
    );
    println!(
        "- sig({:02})  = {:?}",
        sig.len(),
        util::to_hex_str(sig.as_slice_less_safe())
    );
    println!(
        "- message({:02})  = {:?}",
        message.len(),
        util::to_hex_str(message.as_slice_less_safe())
    );
    */

    // verify
    let result = signature::verify(
        &signature::ECDSA_P256_SHA256_ASN1,
        *public_key_der,
        message,
        sig,
    );

    //println!("verify result = {:?}", result);

    match result {
        Ok(()) => true,
        Err(ring::error::Unspecified) => false,
    }
}

fn verify_rpid(rpid: &str, rpid_hash: &[u8]) -> bool {
    // SHA-256(rpid) == attestation.RpIdHash
    let rpid_hash_a = {
        let hash = digest::digest(&digest::SHA256, rpid.as_bytes());
        util::to_hex_str(hash.as_ref())
    };

    let rpid_hash_b = util::to_hex_str(rpid_hash);

    if rpid_hash_a == rpid_hash_b {
        true
    } else {
        false
    }
}
