# Credential management

This command manages discoverable credentials(resident key) in the authenticator.<br>[Spec: 6.8. authenticatorCredentialManagement (0x0A)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorCredentialManagement)



To use this feature, the Authenticator must implement `CredMgmt` or `CredentialMgmtPreview`. check with `enable_info_option()`

```rust
fn is_supported(device: &FidoKeyHid) -> Result<bool> {
    if device.enable_info_option(&InfoOption::CredMgmt)?.is_some() {
        return Ok(true);
    }

    if device
        .enable_info_option(&&InfoOption::CredentialMgmtPreview)?
        .is_some()
    {
        Ok(true)
    } else {
        Ok(false)
    }
}
```

>  [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/7b5b70a07bd7e8f7a82023375539824c3f7343fd/examples/ctapcli/cred.rs#L67-L80)



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

match device.credential_management_delete_credential(Some(pin), pkcd) {
    Ok(_) => println!("- success"),
    Err(e) => println!("- error: {:?}",e),
}
```

