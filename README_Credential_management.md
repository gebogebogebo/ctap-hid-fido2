# Credential management

### authenticatorCredentialManagement

This command manages discoverable credentials(resident key) in the authenticator.<br>[6.8. authenticatorCredentialManagement (0x0A)](https://fidoalliance.org/specs/fido-v2.1-rd-20210309/fido-client-to-authenticator-protocol-v2.1-rd-20210309.html#authenticatorCredentialManagement)



#### credential_management_get_creds_metadata()

Get discoverable credentials metadata.

``` rust
match ctap_hid_fido2::credential_management_get_creds_metadata(
    &Cfg::init(),
    pin,
) {
    Ok(result) => println!("{}", result),
    Err(e) => println!("- error: {:?}", e),
};
```



#### credential_management_enumerate_rps()

Enumerate RPs present on the authenticator.

```rust
match ctap_hid_fido2::credential_management_enumerate_rps(&Cfg::init(), pin)
{
    Ok(results) => {
        for r in results {
            println!("## rps\n{}", r);
        }
    }
    Err(e) => println!("- error: {:?}", e),
}
```



#### credential_management_enumerate_credentials()

Enumerate the credentials for a RP.

```rust
match ctap_hid_fido2::credential_management_enumerate_credentials(
    &Cfg::init(),
    pin,
    rpid_hash_bytes,
) {
    Ok(results) => {
        for c in results {
            println!("## credentials\n{}", c);
        }
    }
    Err(e) => println!("- error: {:?}", e),
}
```



#### credential_management_delete_credential()

Delete a credential.

```rust
let mut pkcd = PublicKeyCredentialDescriptor::default();
pkcd.id = util::to_str_hex(credential_id.unwrap());
pkcd.ctype = "public_key".to_string();

match ctap_hid_fido2::credential_management_delete_credential(
    &Cfg::init(),
    pin,
    Some(pkcd),
) {
    Ok(_) => println!("- success"),
    Err(e) => println!("- error: {:?}",e),
}
```



### 