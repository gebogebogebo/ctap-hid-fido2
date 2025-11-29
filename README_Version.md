## Version
### Ver 3.5.7

- Support for the optional salt.
  - - [with HMAC Secret Extension (use optional salt)](https://github.com/gebogebogebo/ctap-hid-fido2/blob/769d2770ac4a1796ce018e3aa0d50c06f9db15f7/examples/test-with-pin-non-rk/main.rs#L431-L512)

### Ver 3.5.6

- Bugfix.
- Dependency Updates.

### Ver 3.5.5

- Minor updates.

### Ver 3.5.4

- Changed the management method of CID (Channel identifier).
- Dependency Updates.

### Ver 3.5.3

- Dependency Updates.
- Changed from serde_cbor to ciborium.

### Ver 3.5.2

- Dependency Updates.

### Ver 3.5.1

- Dependency Updates.

### Ver 3.5.0

- Specify multiple key_types in MakeCredentialArgsBuilder.
- ED25519 support.
- update dependencies → base64, x509-parser, hidapi, clap, env_logger
- remove dependencies → serde_json, ihex, base64-url

### Ver 3.4.2

- update dependencies → aes, cbc, x509-parser, rpassword
- remove dependencies → block-modes

### Ver 3.4.1

- Bug fix

### Ver 3.4.0

- Update `MakeCredentialArgs` 
  - change `rkparam` → `user_entity`
  - add `resident_key`
  - examples → [discoverable credentials/resident-key](https://github.com/gebogebogebo/ctap-hid-fido2/blob/5c8a4c8e9517bf305b41589ddc0343ea3a9ae994/examples/test-with-pin-rk/main.rs#L53-L118)

### Ver 3.3.1

- Implement `Authenticator Confi`g - `force_change_pin()`. → [Authenticator Config(CTAP 2.1)](README_Authenticator_Config.md)

### Ver 3.3.0

- Implement `Credential Blob Extension`. → [Register and Authenticate Examples](README_Register_and_Authenticate.md)
### Ver 3.2.0
- Implement `Authenticator Config` - `set_min_pin_length()`. → [Authenticator Config(CTAP 2.1)](README_Authenticator_Config.md)
- Implement `Set Min Pin Length Extension`. → [Register and Authenticate Examples](README_Register_and_Authenticate.md)
- Implement `Large Blob` → [Large Blob(CTAP 2.1)](README_Large_Blob.md)
### Ver 3.1.0
- Implement `Authenticator Config` - `toggle_always_uv()`. → [Authenticator Config(CTAP 2.1)](README_Authenticator_Config.md)
- add cli tool [ctapcli](README_ctapcli.md)
### Ver 3.0.0
- The usage has changed from Ver2. → [How to Use](#how-to-use).