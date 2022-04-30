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

>  [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/0c3f73dbf77033bb05ccdabd864e46b981d2b675/examples/ctapcli/config.rs#L36-L45)



## toggle_always_uv()

Toggle Always Require User Verification.

[Spec: 6.11.2. Toggle Always Require User Verification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#toggle-alwaysUv)

```Rust
device.toggle_always_uv(Some(&pin))?;
let result = device.enable_info_option(&InfoOption::AlwaysUv)?;
println!("- done. -> {:?} is {:?}", InfoOption::AlwaysUv, result);
```

> [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/0c3f73dbf77033bb05ccdabd864e46b981d2b675/examples/ctapcli/config.rs#L27-L29)



