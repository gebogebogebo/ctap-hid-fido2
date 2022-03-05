# Register and Authenticate




## Builder Pattern Sample

### non-discoverable credentials/non-resident-key

[non_discoverable_credential s](./examples/test-with-pin-non-rk/src/main.rs#L50)



#### with Key Type

→ link

- Verify Assertion in Ed25519 is always false because it is not yet implemented



#### with HMAC Secret Extension

→ link



### discoverable credentials/resident-key

→ link

- user_name and user_display_name are set only when multiple Assertions are acquired.
- If you want to enable UV-user verification, please specify None instead of a PIN.
  make_credential(),get_assertion()





## Legacy Pattern Sample

### non-discoverable credentials/non-resident-key

→ link

- If you want to use Yubikey bio for fingerprint authentication, specify None for pin.



#### Using Key Type

→ link



### discoverable credentials/resident-key

→ link

