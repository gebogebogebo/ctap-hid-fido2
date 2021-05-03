fn main() {

    println!("----- Nitrokey ENTERBOOT start -----");
    // test
    let result = match ctap_hid_fido2::nitrokey::is_bootloader_mode(&ctap_hid_fido2::HidParam::get_default_params()){
        Ok(result) => result,
        Err(e) => {
            println!("- error: {:?}", e);
            return;
        }
    };

    if result {
        println!("Already in bootloader mode.");
    }else{
        // ブートローダーモードに遷移する
        // キーをタッチしてグリーンのランプが点灯した状態で実行すると成功しやすい
        // 紫のランプ高速点滅状態になれば成功
        match ctap_hid_fido2::nitrokey::enter_boot(&ctap_hid_fido2::HidParam::get_default_params()) {
            Ok(_) => println!("enter boot Ok"),
            Err(err) => println!("enter boot Error = {}", err),
        };
    }

    println!("----- Nitrokey ENTERBOOT end -----");
}
