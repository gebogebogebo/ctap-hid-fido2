# Register and Authenticate




## Builder Pattern Sample

- [non-discoverable credentials/non-resident-key](./examples/test-with-pin-non-rk/src/main.rs#L50-L101)

- [with Key Type](./examples/test-with-pin-non-rk/src/main.rs#L103)
  - Verify Assertion in Ed25519 is always false because it is not yet implemented


- [with HMAC Secret Extension](./examples/test-with-pin-non-rk/src/main.rs#L157)



### discoverable credentials/resident-key

→ link

- user_name and user_display_name are set only when multiple Assertions are acquired.
- If you want to enable UV-user verification, please specify None instead of a PIN.
  make_credential(),get_assertion()





## Legacy Pattern Sample

- [non-discoverable credentials/non-resident-key]()
  - If you want to use Yubikey bio for fingerprint authentication, specify None for pin.


- [with Key Type]()

→ link



### discoverable credentials/resident-key

→ link

