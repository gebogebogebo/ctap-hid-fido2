# Register and Authenticate



- [non-discoverable credentials/non-resident-key](https://github.com/gebogebogebo/ctap-hid-fido2/blob/0791003c87b5d36392868a26247fca0b36ed9d5c/examples/test-with-pin-non-rk/main.rs#L63-L114)
  - Most common use to specify PIN.
- [with UV](https://github.com/gebogebogebo/ctap-hid-fido2/blob/0791003c87b5d36392868a26247fca0b36ed9d5c/examples/test-with-pin-non-rk/main.rs#L116-L164)
  - to use Yubikey bio for fingerprint authentication.

- [with Key Type](https://github.com/gebogebogebo/ctap-hid-fido2/blob/0791003c87b5d36392868a26247fca0b36ed9d5c/examples/test-with-pin-non-rk/main.rs#L166-L223)
  - Specify the algorithm(`Ecdsa256`/`Ed25519`).
  - Verify Assertion in `Ed25519` is always false because it is not yet implemented.


- [with HMAC Secret Extension](https://github.com/gebogebogebo/ctap-hid-fido2/blob/0791003c87b5d36392868a26247fca0b36ed9d5c/examples/test-with-pin-non-rk/main.rs#L225-L280)
- I do not know the correct use of this option.


- [discoverable credentials/resident-key](https://github.com/gebogebogebo/ctap-hid-fido2/blob/0791003c87b5d36392868a26247fca0b36ed9d5c/examples/test-with-pin-rk/main.rs#L49-L113)
  - User data can be stored in the authenticator.
  - user_name and user_display_name are set only when multiple Assertions are acquired.
- [without PIN](https://github.com/gebogebogebo/ctap-hid-fido2/blob/0791003c87b5d36392868a26247fca0b36ed9d5c/examples/test-with-pin-non-rk/main.rs#L282-L333)
  - **For security reasons, this feature is deprecated**
  - Use `without_pin_and_uv` to run with an Authenticator that does not have a PIN set.
  - Using `without_pin_and_uv` on an Authenticator with a PIN set may result in an error (behavior depends on Authenticator type).
  - Get whether PIN is set in Authenticator with `enable_info_option()`
    - [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/0791003c87b5d36392868a26247fca0b36ed9d5c/examples/get-info/main.rs#L44-L49)



## Legacy Pattern Sample

- [non-discoverable credentials/non-resident-key](https://github.com/gebogebogebo/ctap-hid-fido2/blob/0791003c87b5d36392868a26247fca0b36ed9d5c/examples/test-with-pin-non-rk/main.rs#L352-L394)


- [with Key Type](https://github.com/gebogebogebo/ctap-hid-fido2/blob/0791003c87b5d36392868a26247fca0b36ed9d5c/examples/test-with-pin-non-rk/main.rs#L396-L444)

- [discoverable credentials/resident-key](https://github.com/gebogebogebo/ctap-hid-fido2/blob/0791003c87b5d36392868a26247fca0b36ed9d5c/examples/test-with-pin-rk/main.rs#L125-L183)



