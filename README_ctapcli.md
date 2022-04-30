# ctapcli

FIDO2 Authenticator Tool

- for macOS

  

## Install

```zsh
brew tap gebogebogebo/tap
brew install ctapcli
```



## Usage Example

```zsh
% ctapcli -h

ctapcli 3.1.0
gebo
This tool implements CTAP HID and can communicate with FIDO Authenticator.

about CTAP(Client to Authenticator Protocol)
https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-
20210615.html

USAGE:
    ctapcli [OPTIONS] [SUBCOMMAND]

OPTIONS:
    -d, --device           Enumerate HID devices.
    -f, --fidokey          Enumerate FIDO key.
    -h, --help             Print help information
    -u, --user-presence    User Presence Test.
    -V, --version          Print version information
    -w, --wink             Blink the LED on the FIDO key.

SUBCOMMANDS:
    bio       Bio management.
                  - List registered biometric authenticate data without any FLAGS and OPTIONS.
    config    Authenticator Config.
    cred      Credential management.
                  - List discoverable credentials without any FLAGS and OPTIONS.
    help      Print this message or the help of the given subcommand(s)
    info      Get Authenticator infomation.
                  - List All Infomation without any FLAGS and OPTIONS.
    memo      Record some short texts in Authenticator.
                  - Get a Memo without any FLAGS and OPTIONS.
    pin       PIN management.
                  - Get PIN retry counter without any FLAGS and OPTIONS.
```



### Get the Authenticator PIN infomation.

```zsh
% ctapcli info -g pin
Get the Authenticator infomation.

option pin = true

This authenticator is capable of accepting a PIN from the client and PIN has been set.
```



### Get PIN retry counter

```zsh
% ctapcli pin        
PIN Management.

Get PIN retry counter.

PIN retry counter = 8

:) :) :) :) :) :) :) :) 

PIN retry counter represents the number of attempts left before PIN is disabled.
Each correct PIN entry resets the PIN retry counters back to their maximum values.
Each incorrect PIN entry decrements the counter by 1.
Once the PIN retry counter reaches 0, built-in user verification are disabled and can only be enabled if authenticator is reset.


Get UV retry counter.

UV retry counter = 3

UV retries count is the number of built-in UV attempts remaining before built-in UV is disabled on the device.
```



### Set new PIN

```zsh
% ctapcli pin -n
PIN Management.

Set new PIN.

new PIN:
[xxxx]

Success! :)
```



### Change PIN

```zsh
% ctapcli pin -c
PIN Management.

Change PIN.

current PIN:
[xxxx]

new PIN:
[zzzz]

Success! :)
```



### Get HID info

```zsh
% ctapcli -f

Enumerate FIDO keys.
- vid=0x1050 , pid=0x0402 , info="product=YubiKey FIDO usage_page=61904 usage=1 serial_number= path=\"IOService:/AppleACPIPlatformExpert/PCI0@0/AppleACPIPCI/XHC1@14/XHC1@14000000/HS04@14400000/YubiKey FIDO@14400000/IOUSBHostInterface@0/AppleUserUSBHostHIDDevice\""
```



### Record some short texts in Authenticator

#### Add a memo.

```shell
% ctapcli memo -a
Record some short texts in Authenticator.

Add a memo.
PIN: [xxxx]

tag:
test

memo:
hoge

- Touch the sensor on the authenticator
Add Success! :)
```

#### Get a memo.

```shell
% ctapcli memo   
Record some short texts in Authenticator.

Get a memo.
PIN: [xxxx]

- test
- aaa
(2/10)

tag:
[test]

Copied it to the clipboard :) :) :) !
```