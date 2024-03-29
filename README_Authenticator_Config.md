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

>  [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/c0b8279335b3387d6307731602e59655b7cc5517/examples/ctapcli/config.rs#L60-L66)



## toggle_always_uv()

Toggle Always Require User Verification.

[Spec: 6.11.2. Toggle Always Require User Verification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#toggle-alwaysUv)

```rust
device.toggle_always_uv(Some(&pin))?;
```

> [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/c0b8279335b3387d6307731602e59655b7cc5517/examples/ctapcli/config.rs#L34)



## set_min_pin_length()

**WARNING Cannot be restored.**<br>Change minimum PIN Length.

[Spec: 6.11.4. Setting a minimum PIN Length](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#setMinPINLength)

```rust
device.set_min_pin_length(new_min_pin_length, Some(&pin))?;
```

> [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/c0b8279335b3387d6307731602e59655b7cc5517/examples/ctapcli/config.rs#L49)



## set_min_pin_length_rpids()

**WARNING Cannot be restored.**<br>Set RP IDs which are allowed to get this information via the minPinLength extension.

[Spec: 6.11.4. Setting a minimum PIN Length](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#setMinPINLength)

```rust
device.set_min_pin_length_rpids(rpids, Some(&pin))?;
```

> [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/eba34ec41e16cab12b974652abe368c362edf929/examples/ctapcli/cfg.rs#L67)



## force_change_pin()

**WARNING Cannot be restored.**<br>PIN change is required after this command.<br>The authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION until changePIN is successful.

[Spec: 6.11.4. Setting a minimum PIN Length](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#setMinPINLength)

```rust
device.force_change_pin(Some(&pin))?;
```

> [Example](https://github.com/gebogebogebo/ctap-hid-fido2/blob/eba34ec41e16cab12b974652abe368c362edf929/examples/ctapcli/cfg.rs#L82)



