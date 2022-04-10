# Get Info

### get_info()

[6.4. authenticatorGetInfo (0x04)](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo)

```rust
use ctap_hid_fido2;
use ctap_hid_fido2::Cfg;

fn main() {
    println!("get_info()");
    match ctap_hid_fido2::get_info(&Cfg::init()) {
        Ok(info) => println!("{}", info),
        Err(e) => println!("error: {:?}", e),
    }
}
```

**console**

```sh
get_info()
- versions                      = ["U2F_V2", "FIDO_2_0", "FIDO_2_1_PRE"]
- extensions                    = ["credProtect", "hmac-secret"]
- aaguid(16)                    = EE882879721C491397753DFCCE97072A
- options                       = [("rk", true), ("up", true), ("plat", false), ("clientPin", true), ("credentialMgmtPreview", true)]
- max_msg_size                  = 1200
- pin_uv_auth_protocols         = [1]
- max_credential_count_in_list  = 8
- max_credential_id_length      = 128
- transports                    = ["usb"]
- algorithms                    = [("alg", "-7"), ("type", "public-key"), ("alg", "-8"), ("type", "public-key")]
```



### get_info_u2f()

Created to test [CTAPHID_MSG](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#usb-hid-msg).

```rust
use ctap_hid_fido2;
use ctap_hid_fido2::Cfg;

fn main() {
    println!("get_info_u2f()");
    match ctap_hid_fido2::get_info_u2f(&Cfg::init()) {
        Ok(result) => println!("{:?}", result),
        Err(e) => println!("error: {:?}", e),
    }
}
```

**console**

```sh
get_info_u2f()
"U2F_V2"
```



### get_pin_retries()

[6.5.5.2. Platform getting PIN retries from Authenticator](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#gettingPINRetries)

pinRetries counter represents the number of attempts left before PIN is disabled.

```Rust
use ctap_hid_fido2;
use ctap_hid_fido2::Cfg;

fn main() {
    println!("get_pin_retries()");
    match ctap_hid_fido2::get_pin_retries(&Cfg::init()) {
        Ok(retry) => println!("{}", retry),
        Err(e) => println!("error: {:?}", e),
    };
}
```

**console**

```sh
get_pin_retries()
8
```



### get_uv_retries()

**Yubikey Bio Only**

[6.5.5.3. Platform getting UV Retries from Authenticator](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#gettingUVRetries)

UV retries count is the number of built-in UV attempts remaining before built-in UV is disabled on the device.

```rust
use ctap_hid_fido2;
use ctap_hid_fido2::Cfg;

fn main() {
    println!("get_uv_retries()");
    match ctap_hid_fido2::get_uv_retries(&Cfg::init()) {
        Ok(retry) => println!("{}", retry),
        Err(e) => println!("error: {:?}", e),
    };
}
```



### enable_info_param()

Same as get_info(), but checks if it has a specific feature/version.<br>It is specified by the enum of InfoParam.

```rust
match ctap_hid_fido2::enable_info_param(&Cfg::init(),InfoParam::VersionsFIDO21PRE) {
    Ok(result) => println!("FIDO 2.1 PRE = {:?}", result),
    Err(e) => println!("- error: {:?}", e),
};
```



### enable_info_option()

Same as get_info(), but checks if it has a specific option.<br>It is specified by the enum of InfoOption.

- Result is `Option<bool>`
  - `Some(true)` : option is present and set to true
  - `Some(false)` : option is present and set to false
  - `None` : option is absent

```rust
match ctap_hid_fido2::enable_info_option(&Cfg::init(),InfoOption::BioEnroll) {
    Ok(result) => println!("BioEnroll = {:?}", result),
    Err(e) => println!("- error: {:?}", e),
};
```



### wink()

Just blink the LED on the FIDO key.

```Rust
use ctap_hid_fido2;
use ctap_hid_fido2::Cfg;

fn main() {
    if let Err(msg) = ctap_hid_fido2::wink(&Cfg::init()){
        println!("error: {:?}", msg);
    }
}
```


