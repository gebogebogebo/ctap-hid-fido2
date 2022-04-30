# Authenticator Config

This command is used to configure various authenticator features through the use of its subcommands.<br>[Spec: 6.11. authenticatorConfig (0x0D)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorConfig)



To use this feature, the Authenticator must implement `authnrCfg` . check with `enable_info_option()`

```rust
fn is_supported(device: &FidoKeyHid) -> Result<bool> {
    if device
        .enable_info_option(&&InfoOption::AuthnrCfg)?
        .is_some()
    {
        Ok(true)
    } else {
        Ok(false)
    }
}
```

