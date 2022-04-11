# Credential management

This command manages discoverable credentials(resident key) in the authenticator.<br>[6.8. authenticatorCredentialManagement (0x0A)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorCredentialManagement)



To use this feature, the Authenticator must implement `CredMgmt` or `CredentialMgmtPreview`. check with `enable_info_option()`

```rust
if device.enable_info_option(&InfoOption::CredMgmt)?.is_none()
    && device.enable_info_option(&InfoOption::CredentialMgmtPreview)?.is_none() {
  // This authenticator is not Supported Credential management.
  return;
};
```



## credential_management_get_creds_metadata()

Get discoverable credentials metadata.

``` rust
fn metadata(device: &FidoKeyHid, pin: &str) {
    match device.credential_management_get_creds_metadata(Some(pin)) {
        Ok(result) => println!("{}", result),
        Err(e) => println!("- error: {:?}", e),
    }
}
```



## credential_management_enumerate_rps()

Enumerate RPs present on the authenticator.

```rust
match device.credential_management_enumerate_rps(Some(pin))
{
    Ok(results) => {
        for r in results {
            println!("## rps\n{}", r);
        }
    }
    Err(e) => println!("- error: {:?}", e),
}
```



## credential_management_enumerate_credentials()

Enumerate the credentials for a RP.

```rust
match device.credential_management_enumerate_credentials(Some(pin), rpid_hash_bytes) {
    Ok(results) => {
        for c in results {
            println!("## credentials\n{}", c);
        }
    }
    Err(e) => println!("- error: {:?}", e),
}
```



## credential_management_delete_credential()

Delete a credential.

```rust
let mut pkcd = PublicKeyCredentialDescriptor::default();
pkcd.id = util::to_str_hex(credential_id.unwrap());
pkcd.ctype = "public_key".to_string();

match device.credential_management_delete_credential(Some(pin), Some(pkcd)) {
    Ok(_) => println!("- success"),
    Err(e) => println!("- error: {:?}",e),
}
```

