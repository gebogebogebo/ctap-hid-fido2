use anyhow::{anyhow, Result};
use base64_url;
use ctap_hid_fido2::{util,HidParam,nitrokey};
use ihex::Record;
use serde_json::Value;

fn set_bootloader_mode() -> Result<()> {
    let result = nitrokey::is_bootloader_mode(
        &HidParam::get_default_params(),
    )?;
    if result {
        println!("Already in bootloader mode.");
    } else {
        // ブートローダーモードに遷移する
        // キーをタッチしてグリーンのランプが点灯した状態で実行すると成功しやすい
        // 紫のランプ高速点滅状態になれば成功
        nitrokey::enter_boot(&HidParam::get_default_params())?;
        println!("enter bootloader mode.");
    }
    Ok(())
}

fn segments(reader: &mut ihex::Reader) -> Result<(u64, u64)> {
    let mut segment_start = 0;
    let mut segment_end = 0;

    let mut ela: u64 = 0;
    for rec in reader {
        let rec = rec?;
        //println!("rec: {:?}", rec);

        match rec {
            Record::ExtendedLinearAddress(x) => {
                // python-intelhex reference
                // https://github.com/python-intelhex/intelhex/blob/master/intelhex/__init__.py#L167
                ela = x as u64 * 65536;
            }
            Record::Data { offset, ref value } => {
                let addr = ela + offset as u64;
                if segment_start == 0 {
                    segment_start = addr;
                } else {
                    segment_end = addr + value.len() as u64;
                }
            }
            _ => {}
        }
    }

    if segment_start == 0 || segment_end == 0 || segment_start == segment_end {
        Err(anyhow!("Error ELA"))
    } else {
        Ok((segment_start, segment_end))
    }
}

fn tobinarray(reader: &mut ihex::Reader, start: u64, size: usize) -> Result<Vec<u8>> {
    let mut data: Vec<u8> = vec![];
    let mut ela: u64 = 0;
    for rec in reader {
        if data.len() >= size {
            break;
        }
        let rec = rec?;
        match rec {
            Record::ExtendedLinearAddress(x) => {
                ela = x as u64 * 65536;
            }
            Record::Data { offset, ref value } => {
                let addr = ela + offset as u64;
                if addr == start || data.len() > 0 {
                    data.append(&mut value.to_vec());
                }
            }
            _ => {}
        }
    }

    Ok(data)
}

fn write_firmware(json: String) -> Result<Vec<u8>> {
    // read from json file
    let firmware_json = std::fs::File::open(json)?;
    let v: Value = serde_json::from_reader(firmware_json)?;

    // firmware-data => base64 => bin => string
    let firmware_base64 = {
        if let Value::String(v) = &v["firmware"] {
            v.to_string()
        } else {
            "".to_string()
        }
    };
    let firmware_dec = base64_url::decode(&firmware_base64)?;
    let firmware_str = String::from_utf8(firmware_dec.to_vec())?;

    // get Sig
    let signature_base64 = {
        if let Value::String(v) = &v["versions"][">2.5.3"]["signature"] {
            v.to_string()
        } else {
            "".to_string()
        }
    };
    let signature_dec = base64_url::decode(&signature_base64)?;

    // str -> ihex recs
    let mut reader = ihex::Reader::new(&firmware_str);

    // ih.segments() = [(134238208, 134300340)]
    let seg = segments(&mut reader)?;

    // size = 62132
    //let size = seg.1 - seg.0;

    let chunk = 2048;
    //let chunk = 240;
    for i in (seg.0..seg.1).step_by(chunk) {
        // PEND イテレータを元に戻すために作り直す（もっといい方法ないか）
        let mut reader = ihex::Reader::new(&firmware_str);

        let data = tobinarray(&mut reader, i, chunk)?;
        /*
        println!("{}", i);
        println!(
            "{}:{},{},{},{}",
            data.len(),
            data[0],
            data[1],
            data[2],
            data[3]
        );
        */

        //書き込み！
        nitrokey::write_flash(&HidParam::get_default_params(),i,&data)?;
    }

    Ok(signature_dec)
}

fn main() -> Result<()> {
    println!("----- Nitrokey ENTERBOOT start -----");

    if true {
        set_bootloader_mode()?;
    }

    // write
    if false {

        let signature = write_firmware("/Users/suzuki/tmp/nitro/fido2_firmware.json".to_string())?;
        println!(
            "- signature({:02})    = {:?}",
            signature.len(),
            util::to_hex_str(&signature)
        );

        nitrokey::verify_flash(&HidParam::get_default_params(),&signature)?;
        println!("verify_flash.");
        /*
        print("bootloader is verifying signature...")
        print(f'Trying with {sig.hex()}')
        self.verify_flash(sig)
        print("...pass!")
        success = True
        */
        
    }

    println!("----- Nitrokey ENTERBOOT end -----");

    Ok(())
}
