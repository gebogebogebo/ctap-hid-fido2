// Authenticator API
// CTAP 2.0
pub const AUTHENTICATOR_MAKE_CREDENTIAL: u8 = 0x01;
pub const AUTHENTICATOR_GET_ASSERTION: u8 = 0x02;
pub const AUTHENTICATOR_GET_INFO: u8 = 0x04;
pub const AUTHENTICATOR_CLIENT_PIN: u8 = 0x06;

// CTAP 2.1
// 6.7. authenticatorBioEnrollment (0x09)
//pub const AUTHENTICATOR_BIO_ENROLLMENT: u8 = 0x09;
// 6.12. Prototype authenticatorBioEnrollment (0x40) (For backwards compatibility with "FIDO_2_1_PRE")
pub const AUTHENTICATOR_BIO_ENROLLMENT: u8 = 0x40;

// 6.8. authenticatorCredentialManagement (0x0A)
//pub const AUTHENTICATOR_CREDENTIAL_MANAGEMENT: u8 = 0x0A;
// 6.13. Prototype authenticatorCredentialManagement (0x41) (For backwards compatibility with "FIDO_2_1_PRE" )
pub const AUTHENTICATOR_CREDENTIAL_MANAGEMENT: u8 = 0x41;

pub const AUTHENTICATOR_SELECTION: u8 = 0x0B;
pub const AUTHENTICATOR_CONFIG: u8 = 0x0D;

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
        0x17 => "0x17 CTAP2_ERR_FP_DATABASE_FULL Fingerprint data base is full, e.g., during enrollment.".to_string(),
        0x18 => "0x18 CTAP2_ERR_LARGE_BLOB_STORAGE_FULL Large blob storage is full.".to_string(),
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
        0x3C => "0x3C CTAP2_ERR_UV_BLOCKED built-in user verification is disabled.".to_string(),
        0x3D => "0x3D CTAP2_ERR_INTEGRITY_FAILURE A checksum did not match.".to_string(),
        0x3E => "0x3E CTAP2_ERR_INVALID_SUBCOMMAND The requested subcommand is either invalid or not implemented.".to_string(),
        0x3F => "0x3F CTAP2_ERR_UV_INVALID built-in user verification unsuccessful. The platform should retry.".to_string(),
        0x40 => "0x40 CTAP2_ERR_UNAUTHORIZED_PERMISSION The permissions parameter contains an unauthorized permission.".to_string(),
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

pub(crate) fn get_ctap_last_enroll_sample_status_message(status: u8) -> String {
    match status {
        0x00 => "Good fingerprint capture. 0x00: CTAP2_ENROLL_FEEDBACK_FP_GOOD".to_string(),
        0x01 => "Fingerprint was too high.".to_string(),
        0x02 => "Fingerprint was too low.".to_string(),
        0x03 => "Fingerprint was too left.".to_string(),
        0x04 => "Fingerprint was too right.".to_string(),
        0x05 => "Fingerprint was too fast.".to_string(),
        0x06 => "Fingerprint was too slow.".to_string(),
        0x07 => "Fingerprint was of poor quality.".to_string(),
        0x08 => "Fingerprint was too skewed.".to_string(),
        0x09 => "Fingerprint was too short.".to_string(),
        0x0a => "Merge failure of the capture.".to_string(),
        0x0b => "Fingerprint already exists.".to_string(),
        0x0c => "(this error number is available)".to_string(),
        0x0d => "User did not touch/swipe the authenticator.".to_string(),
        0x0e => "User did not lift the finger off the sensor.".to_string(),
        _ => format!("0x{:X}", status),
    }
}
