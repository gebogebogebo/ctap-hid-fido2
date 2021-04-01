/*!
Utility API
*/

use num::NumCast;
use serde_cbor::Value;
use sha2::{Digest, Sha256};

pub fn to_hex_str(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|n| format!("{:02X}", n))
        .collect::<String>()
}

pub fn to_str_hex(hexstr: String) -> Vec<u8> {
    hex::decode(hexstr).unwrap()
}

pub fn print_typename<T>(_: T) {
    println!("{}", std::any::type_name::<T>());
}

//
// pub crate
//

// for debug
#[allow(dead_code)]
pub(crate) fn is_debug() -> bool {
    false
}

#[allow(dead_code)]
pub(crate) fn cbor_cast_value<T: NumCast>(value: &Value) -> Option<T> {
    if let Value::Integer(x) = value {
        Some(NumCast::from(*x).unwrap())
    } else {
        None
    }
}

#[allow(dead_code)]
pub(crate) fn cbor_value_to_vec_u8(value: &Value) -> Option<Vec<u8>> {
    if let Value::Bytes(xs) = value {
        Some(xs.to_vec())
    } else {
        None
    }
}

#[allow(dead_code)]
pub(crate) fn cbor_value_to_vec_string(value: &Value) -> Option<Vec<String>> {
    if let Value::Array(x) = value {
        let mut strings = [].to_vec();
        for ver in x {
            if let Value::Text(s) = ver {
                strings.push(s.to_string());
            }
        }
        Some(strings)
    } else {
        None
    }
}

#[allow(dead_code)]
pub(crate) fn cbor_value_to_vec_bytes(value: &Value) -> Option<Vec<Vec<u8>>> {
    if let Value::Array(xs) = value {
        let mut bytes = [].to_vec();
        for x in xs {
            if let Value::Bytes(b) = x {
                bytes.push(b.to_vec());
            }
        }
        Some(bytes)
    } else {
        None
    }
}

#[allow(dead_code)]
pub(crate) fn cbor_value_print(value: &Value) {
    match value {
        Value::Bytes(s) => print_typename(s),
        Value::Text(s) => print_typename(s),
        Value::Integer(s) => print_typename(s),
        Value::Map(s) => print_typename(s),
        Value::Array(s) => print_typename(s),
        _ => println!("unknown Value type"),
    };
}

#[allow(dead_code)]
pub(crate) fn create_clientdata_hash(challenge: Vec<u8>) -> Vec<u8> {
    // sha256
    let mut hasher = Sha256::new();
    hasher.update(challenge);
    let result = hasher.finalize();
    result.to_vec()
}

#[allow(dead_code)]
pub(crate) fn get_ctap_status_message(status: u8) -> String {
    match status {
        0x00 => "0x00 CTAP1_ERR_SUCCESS Indicates successful response.".to_string(),
        0x01 => "0x01 CTAP1_ERR_INVALID_COMMAND The command is not a valid CTAP command.".to_string(),
        0x02 => "0x02 CTAP1_ERR_INVALID_PARAMETER The command included an invalid parameter.".to_string(),
        0x03 => "0x03 CTAP1_ERR_INVALID_LENGTH Invalid message or item length.".to_string(),
        0x04 => "0x04 CTAP1_ERR_INVALID_SEQ Invalid message sequencing.".to_string(),
        0x05 => "0x05 CTAP1_ERR_TIMEOUT Message timed out.".to_string(),
        0x06 => "0x06 CTAP1_ERR_CHANNEL_BUSY Channel busy.".to_string(),
        0x0A => "0x0A CTAP1_ERR_LOCK_REQUIRED Command requires channel lock.".to_string(),
        0x0B => "0x0B CTAP1_ERR_INVALID_CHANNEL Command not allowed on this cid.".to_string(),
        0x11 => "0x11 CTAP2_ERR_CBOR_UNEXPECTED_TYPE Invalid/ unexpected CBOR error.".to_string(),
        0x12 => "0x12 CTAP2_ERR_INVALID_CBOR Error when parsing CBOR.".to_string(),
        0x14 => "0x14 CTAP2_ERR_MISSING_PARAMETER Missing non - optional parameter.".to_string(),
        0x15 => "0x15 CTAP2_ERR_LIMIT_EXCEEDED Limit for number of items exceeded.".to_string(),
        0x16 => "0x16 CTAP2_ERR_UNSUPPORTED_EXTENSION Unsupported extension.".to_string(),
        0x19 => "0x19 CTAP2_ERR_CREDENTIAL_EXCLUDED   Valid credential found in the exclude list.".to_string(),
        0x21 => "0x21 CTAP2_ERR_PROCESSING    Processing(Lengthy operation is in progress).".to_string(),
        0x22 => "0x22 CTAP2_ERR_INVALID_CREDENTIAL    Credential not valid for the authenticator.".to_string(),
        0x23 => "0x23 CTAP2_ERR_USER_ACTION_PENDING   Authentication is waiting for user interaction.".to_string(),
        0x24 => "0x24 CTAP2_ERR_OPERATION_PENDING Processing, lengthy operation is in progress.".to_string(),
        0x25 => "0x25 CTAP2_ERR_NO_OPERATIONS No request is pending.".to_string(),
        0x26 => "0x26 CTAP2_ERR_UNSUPPORTED_ALGORITHM Authenticator does not support requested algorithm.".to_string(),
        0x27 => "0x27 CTAP2_ERR_OPERATION_DENIED  Not authorized for requested operation.".to_string(),
        0x28 => "0x28 CTAP2_ERR_KEY_STORE_FULL    Internal key storage is full.".to_string(),
        0x29 => "0x29 CTAP2_ERR_NOT_BUSY  Authenticator cannot cancel as it is not busy.".to_string(),
        0x2A => "0x2A CTAP2_ERR_NO_OPERATION_PENDING No outstanding operations.".to_string(),
        0x2B => "0x2B CTAP2_ERR_UNSUPPORTED_OPTION Unsupported option.".to_string(),
        0x2C => "0x2C CTAP2_ERR_INVALID_OPTION Not a valid option for current operation.".to_string(),
        0x2D => "0x2D CTAP2_ERR_KEEPALIVE_CANCEL  Pending keep alive was cancelled.".to_string(),
        0x2E => "0x2E CTAP2_ERR_NO_CREDENTIALS    No valid credentials provided.".to_string(),
        0x2F => "0x2F CTAP2_ERR_USER_ACTION_TIMEOUT   Timeout waiting for user interaction.".to_string(),
        0x30 => "0x30 CTAP2_ERR_NOT_ALLOWED   Continuation command, such as, authenticatorGetNextAssertion not allowed.".to_string(),
        0x31 => "0x31 CTAP2_ERR_PIN_INVALID   PIN Invalid.".to_string(),
        0x32 => "0x32 CTAP2_ERR_PIN_BLOCKED PIN Blocked.".to_string(),
        0x33 => "0x33 CTAP2_ERR_PIN_AUTH_INVALID PIN authentication, pinAuth, verification failed.".to_string(),
        0x34 => "0x34 CTAP2_ERR_PIN_AUTH_BLOCKED PIN authentication, pinAuth, blocked.Requires power recycle to reset.".to_string(),
        0x35 => "0x35 CTAP2_ERR_PIN_NOT_SET No PIN has been set.".to_string(),
        0x36 => "0x36 CTAP2_ERR_PIN_REQUIRED  PIN is required for the selected operation.".to_string(),
        0x37 => "0x37 CTAP2_ERR_PIN_POLICY_VIOLATION  PIN policy violation.Currently only enforces minimum length.".to_string(),
        0x38 => "0x38 CTAP2_ERR_PIN_TOKEN_EXPIRED pinToken expired on authenticator.".to_string(),
        0x39 => "0x39 CTAP2_ERR_REQUEST_TOO_LARGE Authenticator cannot handle this request due to memory constraints.".to_string(),
        0x3A => "0x3A CTAP2_ERR_ACTION_TIMEOUT The current operation has timed out.".to_string(),
        0x3B => "0x3B CTAP2_ERR_UP_REQUIRED User presence is required for the requested operation.".to_string(),
        0x7F => "0x7F CTAP1_ERR_OTHER Other unspecified error.".to_string(),
        0xDF => "0xDF CTAP2_ERR_SPEC_LAST CTAP 2 spec last error.".to_string(),
        0xE0 => "0xE0 CTAP2_ERR_EXTENSION_FIRST Extension specific error.".to_string(),
        0xEF => "0xEF CTAP2_ERR_EXTENSION_LAST Extension specific error.".to_string(),
        0xF0 => "0xF0 CTAP2_ERR_VENDOR_FIRST Vendor specific error.".to_string(),
        0xff => "0xFF CTAP2_ERR_VENDOR_LAST   Vendor specific error.".to_string(),
        // CTAP仕様にない、謎のステータス
        0x6A => "0x6A BioPass UnKnown Error.".to_string(),
        _ => format!("0x{:X}", status),
    }
}

pub(crate) fn get_u2f_status_message(status: u8) -> String {
    match status {
        0x90 => "SW_NO_ERROR (0x9000): The command completed successfully without error.".to_string(),
        0x69 => "SW_CONDITIONS_NOT_SATISFIED (0x6985): The request was rejected due to test-of-user-presence being required.".to_string(),
        0x6A => "SW_WRONG_DATA (0x6A80): The request was rejected due to an invalid key handle.".to_string(),
        0x67 => "SW_WRONG_LENGTH (0x6700): The length of the request was invalid.".to_string(),
        0x6E => "SW_CLA_NOT_SUPPORTED (0x6E00): The Class byte of the request is not supported.".to_string(),
        0x6D => "SW_INS_NOT_SUPPORTED (0x6D00): The Instruction of the request is not supported.".to_string(),
        _ => format!("0x{:X}", status),
    }
}

#[allow(dead_code)]
pub(crate) fn convert_to_publickey_pem(public_key_der: &[u8]) -> String {
    let mut tmp = vec![];

    // 1.metadata(26byte)
    let meta_header = hex::decode("3059301306072a8648ce3d020106082a8648ce3d030107034200").unwrap();
    tmp.append(&mut meta_header.to_vec());

    tmp.append(&mut public_key_der.to_vec());

    // 1.encode Base64
    let base64_str = base64::encode(tmp);

    // 2. /n　every 64 characters
    let pem_base = {
        let mut pem_base = "".to_string();
        let mut counter = 0;
        for c in base64_str.chars() {
            pem_base = pem_base + &c.to_string();
            if counter == 64 - 1 {
                pem_base = pem_base + &"\n".to_string();
                counter = 0;
            } else {
                counter = counter + 1;
            }
        }
        pem_base + &"\n".to_string()
    };

    // 3. Header and footer
    let pem_data = "-----BEGIN PUBLIC KEY-----\n".to_string()
        + &pem_base
        + &"-----END PUBLIC KEY-----".to_string();

    /*
    println!(
        "- public_key_pem  = {:?}",pem_data
    );
    */

    pem_data
}
