use crate::make_credential_params;
use crate::util;
use ring::digest;
use x509_parser::parse_x509_der;

pub fn verify_attestation(
    rpid: &str,
    challenge: &[u8],
    attestation: &make_credential_params::Attestation,
) {
    if verify_rpid(rpid, &attestation.rpid_hash) == false {
        return;
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
                },
                _ => panic!("x509 parsing failed: {:?}", res),
            }
        };
        cert.tbs_certificate.subject_pki.subject_public_key
    };


    let a = 0;
    /*
    var result = new Result();
    var cert = DerConverter.ToPemCertificate(att.AttStmtX5c);
    var publicKeyforVerify = CryptoBC.GetPublicKeyPEMfromCert(cert);
    if (!string.IsNullOrEmpty(publicKeyforVerify)) {
        result.IsSuccess = VerifyPublicKey(publicKeyforVerify, challenge, att.AuthData, att.AttStmtSig);
    }

    // Verifyの結果によらず
    {
        var decAuthdata = new DecodedAuthData();
        decAuthdata.Decode(att.AuthData);
        result.CredentialID = decAuthdata.CredentialId;
        result.PublicKeyPem = decAuthdata.PublicKeyPem;
    }

    return result;
    */

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
    }else{
        false
    }
}

