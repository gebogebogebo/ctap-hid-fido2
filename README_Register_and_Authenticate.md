# Register and Authenticate




## Builder Pattern Sample

- [non-discoverable credentials/non-resident-key](https://github.com/gebogebogebo/ctap-hid-fido2/blob/511bbc5f64cce744bbbbabaf9bde713f1ed33119/examples/test-with-pin-non-rk/src/main.rs#L53-L104)
  - Most common use to specify PIN.
- [with UV](https://github.com/gebogebogebo/ctap-hid-fido2/blob/511bbc5f64cce744bbbbabaf9bde713f1ed33119/examples/test-with-pin-non-rk/src/main.rs#L106-L155)
  - to use Yubikey bio for fingerprint authentication.

- [with Key Type](https://github.com/gebogebogebo/ctap-hid-fido2/blob/511bbc5f64cce744bbbbabaf9bde713f1ed33119/examples/test-with-pin-non-rk/src/main.rs#L158-L210)
  - Ecdsa256/Ed25519.
  - Verify Assertion in Ed25519 is always false because it is not yet implemented.


- [with HMAC Secret Extension](https://github.com/gebogebogebo/ctap-hid-fido2/blob/511bbc5f64cce744bbbbabaf9bde713f1ed33119/examples/test-with-pin-non-rk/src/main.rs#L212-L267)

  - I do not know the correct use of this option.


- [discoverable credentials/resident-key](https://github.com/gebogebogebo/ctap-hid-fido2/blob/511bbc5f64cce744bbbbabaf9bde713f1ed33119/examples/test-with-pin-rk/src/main.rs#L37-L102)
  - User data can be stored in the authenticator.
  - user_name and user_display_name are set only when multiple Assertions are acquired.




## Legacy Pattern Sample

- [non-discoverable credentials/non-resident-key](https://github.com/gebogebogebo/ctap-hid-fido2/blob/511bbc5f64cce744bbbbabaf9bde713f1ed33119/examples/test-with-pin-non-rk/src/main.rs#L286-L338)


- [with Key Type](https://github.com/gebogebogebo/ctap-hid-fido2/blob/511bbc5f64cce744bbbbabaf9bde713f1ed33119/examples/test-with-pin-non-rk/src/main.rs#L340-L393)

- [discoverable credentials/resident-key](https://github.com/gebogebogebo/ctap-hid-fido2/blob/511bbc5f64cce744bbbbabaf9bde713f1ed33119/examples/test-with-pin-rk/src/main.rs#L114-L173)



