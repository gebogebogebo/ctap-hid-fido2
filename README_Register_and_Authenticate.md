# Register and Authenticate




## Builder Pattern Sample

- [non-discoverable credentials/non-resident-key](./examples/test-with-pin-non-rk/src/main.rs#L53-L104)
  - Most common use to specify PIN.
- [with UV](./examples/test-with-pin-non-rk/src/main.rs#L106-L155)
  - to use Yubikey bio for fingerprint authentication.

- [with Key Type](./examples/test-with-pin-non-rk/src/main.rs#L158-L210)
  - Ecdsa256/Ed25519.
  - Verify Assertion in Ed25519 is always false because it is not yet implemented.


- [with HMAC Secret Extension](./examples/test-with-pin-non-rk/src/main.rs#L212-L267)
- I do not know the correct use of this option.


- [discoverable credentials/resident-key](./examples/test-with-pin-rk/src/main.rs#L37-L102)
  - User data can be stored in the authenticator.
  - user_name and user_display_name are set only when multiple Assertions are acquired.




## Legacy Pattern Sample

- [non-discoverable credentials/non-resident-key]()


- [with Key Type]()

- [discoverable credentials/resident-key]()



