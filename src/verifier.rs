use crate::make_credential_params;
use crate::util;
use ring::digest;

pub fn verify_attestation(
    rpid: &str,
    challenge: &[u8],
    attestatin: &make_credential_params::Attestation,
) {
    if verify_rpid(rpid, &attestatin.rpid_hash) == false {
        return;
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
    }else{
        false
    }
}

/*
public Result Verify(string rpid,byte[] challenge, Attestation att)
        {
            if (VerifyRpId(rpid, att.RpIdHash) == false) return new Result();
            return (Verify(challenge, att));
        }
*/
