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
    
    let records = &[
        Record::Data { offset: 0x0010, value: vec![0x48,0x65,0x6C,0x6C,0x6F] },
        //Record::Data { offset: 0x0010, value: firmware_bin.to_vec() },
        Record::EndOfFile
    ];

    let object = ihex::create_object_file_representation(records)?;
    println!("{}", object);

    //let signature = &v["versions"][">2.5.3"]["signature"];

    
    // read firmware file
    println!("----- Nitrokey ENTERBOOT end -----");

    Ok(())
}
