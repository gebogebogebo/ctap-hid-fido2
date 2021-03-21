fn main() {

    // test
    ctap_hid_fido2::nitrokey::solo_bootloader(&ctap_hid_fido2::HidParam::get_default_params());

    // ブートローダーモードに遷移する
    // キーをタッチしてグリーンのランプが点灯した状態で実行すると成功しやすい
    // 紫のランプ高速点滅状態になれば成功
    println!("----- Nitrokey ENTERBOOT start -----");
    match ctap_hid_fido2::nitrokey::enter_boot(&ctap_hid_fido2::HidParam::get_default_params()) {
        Ok(_) => println!("enter boot Ok"),
        Err(err) => println!("enter boot Error = {}", err),
    };
    println!("----- Nitrokey ENTERBOOT end -----");

}
