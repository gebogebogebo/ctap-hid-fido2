## Version
### Ver 3.5.12
- Addressed [issue #126](https://github.com/gebogebogebo/ctap-hid-fido2/issues/126).
- Addressed [pull request #133](https://github.com/gebogebogebo/ctap-hid-fido2/pull/133).
  - Fixed `non_discoverable_credentials` (make_credential / get_assertion) failing under [PIN/UV Auth Protocol Two](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinProto2): `pinUvAuthParam` was always truncated to 16 bytes regardless of the negotiated protocol; Protocol Two now correctly returns the full 32-byte HMAC-SHA-256 output.
  - Fixed the same truncation bug in bio enrollment, credential management, large blobs, and authenticator config commands.
  - Fixed the `hmac-secret` extension to be PIN/UV Auth Protocol-aware (it previously always used Protocol One's shared-secret derivation/truncation regardless of the negotiated protocol).
  - Centralized PIN/UV Auth Protocol version validation and shared-secret handling into a single module, removing duplicated per-protocol branching across the PIN, bio enrollment, credential management, large blobs, and authenticator config code paths.
  - example: [test-with-pin-non-rk](examples/test-with-pin-non-rk/main.rs) / [test-with-pin-rk](examples/test-with-pin-rk/main.rs) now exercise both PIN/UV Auth Protocol One and Two.
- Dependency Updates.

### Ver 3.5.11
- Addressed [issue #127](https://github.com/gebogebogebo/ctap-hid-fido2/issues/127).
- Addressed [pull request #128](https://github.com/gebogebogebo/ctap-hid-fido2/pull/128).
  - Added `keep_alive_msg_to_stderr` to `Cfg` / `FidoKeyHid` (default: `false`). When `true`, the keep-alive user-presence message (e.g. "Touch the sensor on the authenticator") is printed to **stderr** instead of stdout.
  - Added `Cfg::with_keep_alive_msg_to_stderr()`.
  - example: [reg-auth](examples/reg-auth/main.rs) — CLI flags `--enable-log` and `--keep-alive-msg-to-stderr`.
- Addressed [pull request #130](https://github.com/gebogebogebo/ctap-hid-fido2/pull/130).
  - `ctaphid`: gate `CTAPHID_ERROR` and unknown-status `println!` output behind `enable_log` (consistent with other debug logs).
- Dependency Updates.

### Ver 3.5.10
- Addressed [issue #115](https://github.com/gebogebogebo/ctap-hid-fido2/issues/115).
- Addressed [pull request #117](https://github.com/gebogebogebo/ctap-hid-fido2/pull/117).
- Dependency Updates.

### Ver 3.5.9
- Optional crypto backends are now available: ring (default), aws-lc-rs, or fips (aws-lc-rs in FIPS mode).
  - See ReadMe: Cargo features (crypto backend) for details.
- Dependency Updates.

### Ver 3.5.8
- [PIN/UV Auth Protocol Two](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#pinProto2) is now supported.
  - example: [with PIN/UV Auth Protocol Two](https://github.com/gebogebogebo/ctap-hid-fido2/blob/ad3f21c763adeb4ee98fc607f5987f76572b6a41/examples/test-with-pin-non-rk/main.rs#L257-L320)

### Ver 3.5.7

- Support for the optional salt.
  - example: [with HMAC Secret Extension (use optional salt)](https://github.com/gebogebogebo/ctap-hid-fido2/blob/769d2770ac4a1796ce018e3aa0d50c06f9db15f7/examples/test-with-pin-non-rk/main.rs#L431-L512)

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