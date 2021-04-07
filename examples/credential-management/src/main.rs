use ctap_hid_fido2;
use ctap_hid_fido2::util;
extern crate clap;
use clap::{App, Arg, SubCommand};

fn metadata(pin: Option<&str>) {
    println!("# credential_management_get_creds_metadata()");
    match ctap_hid_fido2::credential_management_get_creds_metadata(
        &ctap_hid_fido2::HidParam::get_default_params(),
        pin,
    ) {
        Ok(result) => {
            println!("{}", result);
        }
        Err(error) => {
            println!("- creds metadata error: {:?}", error);
        }
    };
    println!("");
    println!("");
}

fn rps(pin: Option<&str>) {
    println!("# credential_management_enumerate_rps()");
    match ctap_hid_fido2::credential_management_enumerate_rps(
        &ctap_hid_fido2::HidParam::get_default_params(),
        pin,
    ) {
        Ok(results) => {
            for data in results {
                println!("## rps");
                println!("{}",data);
            }
        }
        Err(error) => {
            println!("- enumerate rps error: {:?}", error);
        }
    };
    println!("");
    println!("");
}

fn credentials(pin: Option<&str>) {
    println!("# credential_management_enumerate_credentials()");
    println!("");

    let rpid_hash: Vec<u8> = util::to_str_hex(
        "8C5D729B193185CD17AC242C85E6BD23D3990ABB1C65336559524882A6EACA33".to_string(),
    );
    match ctap_hid_fido2::credential_management_enumerate_credentials(
        &ctap_hid_fido2::HidParam::get_default_params(),
        pin,
        rpid_hash,
    ) {
        Ok(results) => {
            for data in results {
                println!("## credentials");
                println!("{}",data);
            }
        }
        Err(error) => {
            println!("- enumerate credentials error: {:?}", error);
        }
    };
    println!("");
    println!("");
}

fn delete(pin: Option<&str>) {
    println!("# credential_management_delete_credential()");
    println!("");

    let mut pkcd =
        ctap_hid_fido2::credential_management_params::PublicKeyCredentialDescriptor::default();
    pkcd.id = util::to_str_hex(
        "271EDC98A27DF03BB9DAE9F7A85A3249DF4412D0BA2F301ED62E2A03AA44326067B88C5D729B193185CD17AC242C85E6BD23D3990ABB1C65336559524882A6EACA33C4010000".to_string(),
    );
    pkcd.ctype = "public_key".to_string();

    match ctap_hid_fido2::credential_management_delete_credential(
        &ctap_hid_fido2::HidParam::get_default_params(),
        pin,
        Some(pkcd),
    ) {
        Ok(_) => println!("- credential_management_delete_credential Success"),
        Err(error) => println!(
            "- credential_management_delete_credential error: {:?}",
            error
        ),
    };
    println!("");
    println!("");
}

fn update(pin: Option<&str>) {
    println!("credential_management_update_user_information()");

    let mut pkcd =
        ctap_hid_fido2::credential_management_params::PublicKeyCredentialDescriptor::default();
    pkcd.id = util::to_str_hex(
        "2476469AB7113555910F56B21F06D3A3D16D7E5775C67DB0B5CF51D0FB071935AEDC8C5D729B193185CD17AC242C85E6BD23D3990ABB1C65336559524882A6EACA33D1010000".to_string(),
    );
    pkcd.ctype = "public_key".to_string();

    let mut pkcue =
        ctap_hid_fido2::credential_management_params::PublicKeyCredentialUserEntity::default();
    pkcue.id = util::to_str_hex("010203".to_string());
    pkcue.name = "test-name".to_string();
    pkcue.display_name = "test-display-name".to_string();

    match ctap_hid_fido2::credential_management_update_user_information(
        &ctap_hid_fido2::HidParam::get_default_params(),
        pin,
        Some(pkcd),
        Some(pkcue),
    ) {
        Ok(_) => println!("- credential_management_update_user_information Success"),
        Err(error) => println!(
            "- credential_management_update_user_information error: {:?}",
            error
        ),
    };
    println!("");
    println!("");
}

fn main() {
    //println!("# credential_management_get_creds_metadata()");

    // PEND clap
    let app = App::new("credential-management")
        .version("0.1.0")
        .author("gebo")
        .about("CTAP 2.1 credential-management command test app")
        //.arg(Arg::with_name("metadata")
        //.help("credential_management_get_creds_metadata")
        //.required(true)
        //)
        .arg(Arg::with_name("metadata")
            .help("credential_management_get_creds_metadata")
            .short("m")
            .long("metadata")
        )
        .arg(Arg::with_name("rps")
            .help("credential_management_enumerate_rps")
            .short("r")
            .long("rps")
        )
        .arg(Arg::with_name("credentials")
            .help("credential_management_enumerate_credentials")
            .short("c")
            .long("credentials")
        //)     println!("# credential_management_enumerate_credentials()");

        //.arg(Arg::with_name("opt")              // オプションを定義
        //    .help("credential_management_get_creds_metadata")              // ヘルプメッセージ
        //    .short("mx")                         // ショートコマンド
        //    .long("metadatax")                        // ロングコマンド
        //    .takes_value(true)                  // 値を持つことを定義
        //.subcommand(SubCommand::with_name("sub")// サブコマンドを定義
        //    .about("sample subcommand")         // このサブコマンドについて
        //    .arg(Arg::with_name("subflg")       // フラグを定義
        //        .help("sample flag by sub")     // ヘルプメッセージ
        //        .short("f")                     // ショートコマンド
        //        .long("flag")                   // ロングコマンド
        //    )
        );

    // 引数を解析
    let matches = app.get_matches();

    /*
    // paが指定されていれば値を表示
    if let Some(o) = matches.value_of("pa") {
        println!("Value for pa: {}", o);
    }

    // optが指定されていれば値を表示
    if let Some(o) = matches.value_of("opt") {
        println!("Value for opt: {}", o);
    }

    // flgのON/OFFで表示するメッセージを切り替え
    println!("flg is {}", if matches.is_present("flg") {"ON"} else {"OFF"});

    // subサブコマンドの解析結果を取得
    if let Some(ref matches) = matches.subcommand_matches("sub") {
        println!("used sub"); // subが指定されていればメッセージを表示
        // subflgのON/OFFで表示するメッセージを切り替え
        println!("subflg is {}", if matches.is_present("subflg") {"ON"} else {"OFF"});
    }        
    */
    // PEND clap

    // flgのON/OFFで表示するメッセージを切り替え
    println!("metadata is {}", if matches.is_present("metadata") {"ON"} else {"OFF"});
    println!("rps is {}", if matches.is_present("rps") {"ON"} else {"OFF"});
    println!("credentials is {}", if matches.is_present("credentials") {"ON"} else {"OFF"});

    /*
    ctap_hid_fido2::hello();

    match ctap_hid_fido2::enable_ctap_2_1(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => {
            println!("Enable CTAP 2.1 = {:?}",result);
        }
        Err(error) => {
            println!("- error: {:?}", error);
        }
    };

    println!("----- credential-management start -----");
    metadata(Some("1234"));
    rps(Some("1234"));
    credentials(Some("1234"));
    delete(Some("1234"));
    update(Some("1234"));
    println!("----- credential-management end -----");
    */

    /* Test for CTAP 2.1
    match ctap_hid_fido2::config(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => {
            println!("- config : {:?}", result);
        }
        Err(error) => {
            println!("- config error: {:?}", error);
        }
    };

    match ctap_hid_fido2::selection(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(result) => {
            println!("- selection : {:?}", result);
        }
        Err(error) => {
            println!("- selection error: {:?}", error);
        }
    };
    */
}
