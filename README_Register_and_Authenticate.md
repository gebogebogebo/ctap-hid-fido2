# Register and Authenticate

To be secure, it is recommended to use a separate implementation for server and client.



## Register

1. create `Challenge`

Correct implementation is done on the server side.

```rust
let challenge = verifier::create_challenge();
```

2. create `MakeCredentialArgs`

- need `rpid(string)` and `challenge`
- set `pin(string)`

```rust
let make_credential_args = MakeCredentialArgsBuilder::new(&rpid, &challenge)
  .pin(pin)
  .build();
```

3. create `FidoKeyHid`

```rust
let device = FidoKeyHidFactory::create(&cfg)?;
```

4. get `Attestation` Object

```rust
let attestation = device.make_credential_with_args(&make_credential_args)?;
```

5. verify `Attestation` Object

Correct implementation is done on the server side.

- need `rpid(string)` and `challenge` and `Attestation`

```rust
let verify_result = verifier::verify_attestation(rpid, &challenge, &attestation);
if verify_result.is_success {
  println!("-- Verify Attestation Success");
} else {
  println!("-- ! Verify Attestation Failed");
}
```

6. store **Credential Id** and **Publickey**

Correct implementation is done on the server side.

```rust
let userdata.credential_id = verify_result.credential_id;
let userdata.credential_public_key = verify_result.credential_public_key;

store(&userdata); <- ex.store to database
```

 

## Authenticate

1. restore **Credential Id** and **Publickey**

Correct implementation is done on the server side.

```rust
let userdata = restore(userid); <- ex.restore from database

userdata.credential_id;
userdata.credential_public_key;
```

2. create `Challenge`

Correct implementation is done on the server side.

```rust
let challenge = verifier::create_challenge();
```

3. create `GetAssertionArgs`

- need `rpid(string)` and `challenge`
- set `pin(string)`  and **Credential Id**

```rust
let get_assertion_args = GetAssertionArgsBuilder::new(rpid, &challenge)
  .pin(pin)
  .credential_id(&userdata.credential_id)
  .build();
```

4. get `Assertion` Object

```rust
let assertions = device.get_assertion_with_args(&get_assertion_args)?;
```

5. verify `Assertion` Object

Correct implementation is done on the server side.

- need `rpid(string)` and **PublicKey** and `challenge` and `Assertion`

```rust
let is_success = verifier::verify_assertion(
  rpid,
  &userdata.credential_public_key,
  &challenge,
  &assertions[0],
);
if is_success {
  println!("-- Verify Assertion Success");
} else {
  println!("-- ! Verify Assertion Failed");
}
```



## Examples

### non-discoverable credentials/non-resident-key

- [non-discoverable credentials/non-resident-key](https://github.com/gebogebogebo/ctap-hid-fido2/blob/4554732f4647b0bce0d7674c554a7a33dabf099a/examples/test-with-pin-non-rk/main.rs#L69-L120)
  - Most common use to specify PIN.
- [with UV](https://github.com/gebogebogebo/ctap-hid-fido2/blob/4554732f4647b0bce0d7674c554a7a33dabf099a/examples/test-with-pin-non-rk/main.rs#L122-L170)
  - to use Yubikey bio for fingerprint authentication.
- [with Key Type](https://github.com/gebogebogebo/ctap-hid-fido2/blob/4554732f4647b0bce0d7674c554a7a33dabf099a/examples/test-with-pin-non-rk/main.rs#L172-L230)
  - Specify the algorithm(`Ecdsa256`/`Ed25519`).


- [with HMAC Secret Extension](https://github.com/gebogebogebo/ctap-hid-fido2/blob/4554732f4647b0bce0d7674c554a7a33dabf099a/examples/test-with-pin-non-rk/main.rs#L232-L315)
- [with HMAC Secret Extension (use optional salt)](https://github.com/gebogebogebo/ctap-hid-fido2/blob/769d2770ac4a1796ce018e3aa0d50c06f9db15f7/examples/test-with-pin-non-rk/main.rs#L431-L512)
  - I do not know the correct use of this option.
- [with Large Blob Key Extension](https://github.com/gebogebogebo/ctap-hid-fido2/blob/4554732f4647b0bce0d7674c554a7a33dabf099a/examples/test-with-pin-non-rk/main.rs#L370-L455)
  - Used with Large Blob Command.
  - [Spec: 6.10.5. Writing per-credential large-blob data for a new credential](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#writing-per-credential-data)
  
- [with Min Pin Length Extension](https://github.com/gebogebogebo/ctap-hid-fido2/blob/4554732f4647b0bce0d7674c554a7a33dabf099a/examples/test-with-pin-non-rk/main.rs#L457-L490)
  - Get Min Pin Length Policy.
  - RPID must be set in Authenticator Config. → [Authenticator Config](README_Authenticator_Config.md)
  - [Spec: 12.4. Minimum PIN Length Extension (minPinLength)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-minpinlength-extension)
  
- [without PIN](https://github.com/gebogebogebo/ctap-hid-fido2/blob/4554732f4647b0bce0d7674c554a7a33dabf099a/examples/test-with-pin-non-rk/main.rs#L317-L368)
  - **For security reasons, this feature is deprecated**
  
  - Use `without_pin_and_uv` to run with an Authenticator that does not have a PIN set.
  
  - Using `without_pin_and_uv` on an Authenticator with a PIN set may result in an error (behavior depends on Authenticator type).
  
  - Get whether PIN is set in Authenticator with `enable_info_option()`
    - [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/0791003c87b5d36392868a26247fca0b36ed9d5c/examples/get-info/main.rs#L44-L49)

- [with PIN/UV Auth Protocol Two](https://github.com/gebogebogebo/ctap-hid-fido2/blob/ad3f21c763adeb4ee98fc607f5987f76572b6a41/examples/test-with-pin-non-rk/main.rs#L257-L320)
  - use `device.set_pin_uv_auth_protocol_two()`.

### discoverable credentials/resident-key

- [discoverable credentials/resident-key](https://github.com/gebogebogebo/ctap-hid-fido2/blob/4554732f4647b0bce0d7674c554a7a33dabf099a/examples/test-with-pin-rk/main.rs#L53-L118)
  - User data can be stored in the authenticator.
  - user_name and user_display_name are set only when multiple Assertions are acquired.
- [with Credential Blob Extension](https://github.com/gebogebogebo/ctap-hid-fido2/blob/4554732f4647b0bce0d7674c554a7a33dabf099a/examples/test-with-pin-rk/main.rs#L120-L235)
  - This extension enables RPs to provide a small amount of extra credential configuration.
  - This extension only works if CTAP 2.1 is implemented.



## Legacy Pattern Examples

Legacy patterns are **deprecated.**
They will be removed in a future version.

- [non-discoverable credentials/non-resident-key](https://github.com/gebogebogebo/ctap-hid-fido2/blob/4554732f4647b0bce0d7674c554a7a33dabf099a/examples/test-with-pin-non-rk/main.rs#L511-L553)


- [with Key Type](https://github.com/gebogebogebo/ctap-hid-fido2/blob/4554732f4647b0bce0d7674c554a7a33dabf099a/examples/test-with-pin-non-rk/main.rs#L555-L603)

- [discoverable credentials/resident-key](https://github.com/gebogebogebo/ctap-hid-fido2/blob/4554732f4647b0bce0d7674c554a7a33dabf099a/examples/test-with-pin-rk/main.rs#L237-L295)



