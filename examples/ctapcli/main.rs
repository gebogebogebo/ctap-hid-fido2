use anyhow::{anyhow, Result};

extern crate clap;
use clap::{Parser, Subcommand};

extern crate arboard;

extern crate rpassword;

#[allow(unused_imports)]
use ctap_hid_fido2::util;
use ctap_hid_fido2::{str_buf, Cfg, FidoKeyHid, FidoKeyHidFactory};

use ctap_hid_fido2::fidokey::get_info::InfoParam;

mod bio;
mod blob;
mod cfg;
mod common;
mod cred;
mod info;
mod memo;
mod pin;

#[derive(Parser)]
#[clap(
    name = "ctapcli",
    author = "gebo",
    version = env!("CARGO_PKG_VERSION"),
    about = "This tool implements CTAP HID and can communicate with FIDO Authenticator.\n\nabout CTAP(Client to Authenticator Protocol)\nhttps://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html"
)]
struct AppArg {
    #[clap(short = 'd', long = "device", help = "Enumerate HID devices.")]
    device: bool,

    #[clap(short = 'f', long = "fidokey", help = "Enumerate FIDO key.")]
    fidokey: bool,

    #[clap(short = 'w', long = "wink", help = "Blink the LED on the FIDO key.")]
    wink: bool,

    #[clap(short = 'u', long = "user-presence", help = "User Presence Test.")]
    user_presence: bool,

    #[clap(subcommand)]
    action: Option<Action>,
}

#[derive(Subcommand)]
enum Action {
    #[clap(
        about = "Get Authenticator infomation.\n- List All Infomation without any FLAGS and OPTIONS."
    )]
    Info {
        #[clap(short = 'l', long = "list", help = "List all info.")]
        list: bool,

        #[clap(
            short = 'g',
            long = "get",
            help = "Get a info.\n- a/rk/up/uv/plat/pin/mgmtp/mgmt/biop/bio/auv/ep/minpin/\n  u2f_v2/fido2/fido21p/fido21/hmac."
        )]
        item: Option<String>,
    },

    #[clap(about = "PIN management.\n- Get PIN retry counter without any FLAGS and OPTIONS.")]
    Pin {
        #[clap(short = 'n', long = "new", help = "Set new pin.")]
        new: bool,

        #[clap(short = 'c', long = "change", help = "Change pin.")]
        change: bool,

        #[clap(short = 'v', long = "view", help = "View pin retry count.")]
        view: bool,
    },

    #[clap(
        about = "Record some short texts in Authenticator.\n- Get a Memo without any FLAGS and OPTIONS."
    )]
    Memo {
        #[clap(short = 'a', long = "add", help = "Add a memo.")]
        add: bool,

        #[clap(
            short = 'g',
            long = "get",
            value_name = "tag",
            default_value = "",
            help = "Get a memo to Clipboard."
        )]
        get_tag: String,

        #[clap(
            short = 'd',
            long = "del",
            value_name = "tag",
            default_value = "",
            help = "Delete a memo."
        )]
        del_tag: String,

        #[clap(short = 'l', long = "list", help = "List all memos.")]
        list: bool,
    },

    #[clap(
        about = "Bio management.\n- List registered biometric authenticate data without any FLAGS and OPTIONS."
    )]
    Bio {
        #[clap(short = 'l', long = "list", help = "List registered bio.")]
        list: bool,

        #[clap(short = 'i', long = "info", help = "Display sensor info.")]
        info: bool,

        #[clap(short = 'e', long = "enroll", help = "Enrolling fingerprint.")]
        enroll: bool,

        #[clap(
            short = 'd',
            long = "delete",
            value_name = "template-id",
            help = "Delete fingerprint."
        )]
        delete_template_id: Option<String>,

        #[clap(long = "test", help = "Test register and authenticate.")]
        test: bool,

        #[clap(
            long = "test-with-log",
            help = "Test register and authenticate(with log)."
        )]
        test_with_log: bool,
    },

    #[clap(
        about = "Credential management.\n- List discoverable credentials without any FLAGS and OPTIONS."
    )]
    Cred {
        #[clap(short = 'l', long = "list", help = "List discoverable credentials.")]
        list: bool,

        #[clap(
            short = 'm',
            long = "metadata",
            help = "Getting discoverable credentials Metadata."
        )]
        metadata: bool,

        #[clap(
            short = 'd',
            long = "delete",
            help = "Delete a discoverable credential."
        )]
        delete: bool,

        #[clap(
            short = 'u',
            long = "update",
            help = "[Always an error]Update a discoverable credential user info."
        )]
        update: bool,

        #[clap(
            long = "rpid",
            help = "rpid to be deleted(or updated)."
        )]
        rpid: Option<String>,

        #[clap(
            long = "userid",
            help = "user-id to be deleted(or updated)."
        )]
        userid: Option<String>,

        #[clap(short = 'p')]
        pin: Option<String>,
    },
    #[clap(about = "Authenticator Config.\n- Configure various authenticator features.")]
    Config {
        #[clap(long = "auv", help = "Toggle Always Require User Verification.")]
        toggle_always_uv: bool,

        #[clap(
            long = "minpin",
            value_name = "new-min-pin-length",
            help = "Setting a minimum PIN Length."
        )]
        new_min_pin_length: Option<u8>,

        #[clap(
            long = "rpid", 
            help = "xxx.")]
        rpids: Option<Vec<String>>,

        #[clap(
            long = "fcp",
            help = "PIN change is required after this command.\nThe authenticator returns CTAP2_ERR_PIN_POLICY_VIOLATION until changePIN is successful."
        )]
        force_change_pin: bool,

        #[clap(short = 'p')]
        pin: Option<String>,
    },
    #[clap(
        about = "Large Blob.\n- Large amount of information can be stored in the security key."
    )]
    Blob {
        #[clap(long = "get", help = "Get Large Blob Data.")]
        get: bool,

        #[clap(
            long = "set",
            value_name = "string value",
            help = "String to set to Large Blob."
        )]
        str_val: Option<String>,

        #[clap(short = 'p')]
        pin: Option<String>,
    },
}

fn main() -> Result<()> {
    env_logger::init();
    let arg: AppArg = AppArg::parse();

    let mut cfg = Cfg::init();
    cfg.enable_log = false;
    cfg.use_pre_bio_enrollment = true;
    cfg.use_pre_credential_management = true;

    if arg.device {
        println!("Enumerate HID devices.");
        let devs = ctap_hid_fido2::get_hid_devices();
        for info in devs {
            println!(
                "- vid=0x{:04x} , pid=0x{:04x} , info={:?}",
                info.vid, info.pid, info.info
            );
        }
    }

    if arg.fidokey {
        println!("Enumerate FIDO keys.");
        let devs = ctap_hid_fido2::get_fidokey_devices();
        for info in devs {
            println!(
                "- vid=0x{:04x} , pid=0x{:04x} , info={:?}",
                info.vid, info.pid, info.info
            );
        }
    }

    let device = FidoKeyHidFactory::create(&cfg)?;

    if arg.user_presence {
        println!("User Presence Test.\n");
        up(&device)?;
    }

    if arg.wink {
        println!("Blink LED on FIDO key.\n");
        device.wink()?;
        println!("Do you see that wink? ;-)\n");
    }

    if let Some(action) = arg.action {
        match action {
            Action::Info { item, list } => {
                println!("Get the Authenticator infomation.\n");
                let item_val = if list {
                    "".to_string()
                } else {
                    item.unwrap_or_default()
                };
                info::info(&device, &item_val)?;
            }
            Action::Pin {
                new,
                change,
                view: _,
            } => {
                println!("PIN Management.\n");
                let command = if new {
                    pin::PinCommand::New
                } else if change {
                    pin::PinCommand::Change
                } else {
                    pin::PinCommand::View
                };
                pin::pin(&device, command)?;
            }
            Action::Memo {
                add,
                list,
                get_tag,
                del_tag,
            } => {
                println!("Record some short texts in Authenticator.\n");

                let command = if add {
                    memo::Command::Add
                } else if list {
                    memo::Command::List
                } else if !del_tag.is_empty() {
                    memo::Command::Del(del_tag)
                } else {
                    memo::Command::Get(get_tag)
                };

                memo::memo(&device, command)?;
            }
            Action::Bio {
                list: _,
                info,
                enroll,
                delete_template_id,
                test,
                test_with_log,
            } => {
                println!("Bio Management.\n");

                let command = if info {
                    bio::Command::Info
                } else if enroll {
                    bio::Command::Enroll
                } else if let Some(template_id) = delete_template_id {
                    bio::Command::Del(template_id)
                } else if test {
                    bio::Command::Test(false)
                } else if test_with_log {
                    bio::Command::Test(true)
                } else {
                    bio::Command::List
                };

                bio::bio(&device, command)?;
            }
            Action::Cred {
                list: _,
                metadata,
                delete,
                update,
                rpid,
                userid,
                pin,
            } => {
                let command = if metadata {
                    cred::Command::Metadata
                } else if delete {
                    cred::Command::Del((
                        rpid.unwrap_or_default(),
                        userid.unwrap_or_default(),
                    ))
                } else if update {
                    cred::Command::Update((
                        rpid.unwrap_or_default(),
                        userid.unwrap_or_default(),
                    ))
                } else {
                    cred::Command::List
                };

                cred::cred(&device, command, pin)?;
            }
            Action::Config {
                toggle_always_uv,
                new_min_pin_length,
                rpids,
                force_change_pin,
                pin,
            } => {
                if toggle_always_uv {
                    cfg::config(&device, cfg::Command::ToggleAlwaysUv, pin)?;
                } else if new_min_pin_length.is_some() {
                    cfg::config(
                        &device,
                        cfg::Command::SetMinPINLength(new_min_pin_length.unwrap()),
                        pin,
                    )?;
                } else if rpids.is_some() {
                    cfg::config(
                        &device,
                        cfg::Command::SetMinPinLengthRPIDs(rpids.unwrap()),
                        pin,
                    )?;
                } else if force_change_pin {
                    cfg::config(&device, cfg::Command::ForceChangePin, pin)?;
                }
            }
            Action::Blob {
                get,
                str_val,
                pin,
            } => {
                if get {
                    blob::blob(&device, blob::Command::Get, None)?;
                } else if let Some(str_val) = str_val {
                    let command = blob::Command::Set(str_val.as_bytes().to_vec());
                    blob::blob(&device, command, pin)?;
                } else {
                    println!("need str.");
                }
            }
        }
    }

    Ok(())
}

pub fn up(device: &FidoKeyHid) -> Result<()> {
    if !device.enable_info_param(&InfoParam::VersionsFido21)? {
        return Err(anyhow!(
            "This authenticator is not supported for this functions."
        ));
    }
    let (cid, _selection_result_str) = device.selection()?;

    // If you need to cancel the selection, you can use cid with device.cancel_selection(&cid)?;
    device.cancel_selection(&cid)?;
    
    Ok(())
}
