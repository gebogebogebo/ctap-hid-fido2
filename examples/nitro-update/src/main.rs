use anyhow::Result;
use serde_json::Value;
use ihex::Record;
use base64::decode;

fn bootloader() {
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
}

fn main() -> Result<()> {

    println!("----- Nitrokey ENTERBOOT start -----");

    if false {
        bootloader();        
    }

    // read from json file
    let firmware_json = std::fs::File::open("/Users/suzuki/tmp/nitro/fido2_firmware.json")?;
    let v: Value = serde_json::from_reader(firmware_json)?;

    // firmware-data => base64 => bin => string
    let firmware_base64 = {
        if let Value::String(v) = &v["firmware"] {
            v.to_string()
        }else{
            "".to_string()
        }
    };
    let firmware_dec = &decode(firmware_base64)?;
    let firmware_str = String::from_utf8(firmware_dec.to_vec())?;

    // str -> ihex recs
    let reader = ihex::Reader::new(&firmware_str);
    for rec in reader {
        //if rec.clone().unwrap().record_type() != 0x00 {
            println!("rec: {:?}", rec);
        //}
    }

    //let result = ihex::create_object_file_representation(reader).unwrap();

    //rec: Ok(Data { offset: 20480, value: [0, 192, 0, 32, 209, 115, 0, 8, 33, 116, 0, 8, 33, 116, 0, 8] })
    //rec: Ok(ExtendedLinearAddress(2048))
    //rec: Ok(ExtendedLinearAddress(2049))
    //rec: Ok(StartLinearAddress(134247377))
    //rec: Ok(EndOfFile)
    let a = 0;


    //let signature = &v["versions"][">2.5.3"]["signature"];

    
    // read firmware file
    println!("----- Nitrokey ENTERBOOT end -----");

    Ok(())
}
