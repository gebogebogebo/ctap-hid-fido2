use anyhow::{anyhow, Result};
use base64_url;
#[allow(unused_imports)]
use ctap_hid_fido2::{nitrokey, util, Cfg};
use ihex::Record;
use serde_json::Value;
extern crate clap;
use clap::{App, Arg};

fn set_bootloader_mode() -> Result<()> {
    let result = nitrokey::is_bootloader_mode(&Cfg::init())?;
    if result {
        println!("Already in bootloader mode.");
    } else {
        println!("Touch until the purple LED flashes fast...");
        nitrokey::enter_boot(&Cfg::init())?;
        println!("Enter bootloader mode.");
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

fn write_firmware(json: &String) -> Result<()> {
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

    // str -> ihex recs
    let mut reader = ihex::Reader::new(&firmware_str);

    let seg = segments(&mut reader)?;

    //let size = seg.1 - seg.0;

    let chunk = 2048;
    //let chunk = 240;
    for i in (seg.0..seg.1).step_by(chunk) {
        // PEND イテレータを元に戻すために作り直す（もっといい方法ないか）
        let mut reader = ihex::Reader::new(&firmware_str);

        let data = tobinarray(&mut reader, i, chunk)?;

        println!("write flash...");
        nitrokey::write_flash(&Cfg::init(), i, &data)?;
    }

    Ok(())
}

fn check_json(json: &String) -> Result<Vec<u8>> {
    let firmware_json = std::fs::File::open(json)?;
    let v: Value = serde_json::from_reader(firmware_json)?;

    let signature_base64 = {
        if let Value::String(v) = &v["versions"][">2.5.3"]["signature"] {
            v.to_string()
        } else {
            "".to_string()
        }
    };
    let signature_dec = base64_url::decode(&signature_base64)?;

    Ok(signature_dec)
}

fn main() -> Result<()> {
    let app = App::new("nitro-update(Non-Formula)")
        .version("0.0.1")
        .author("gebo")
        .about("NitoroKey Firmwware Update Tool")
        .arg(
            Arg::with_name("info")
                .help("Get Firmware Information.")
                .short("i")
                .long("info")
        )
        .arg(
            Arg::with_name("download")
                .help("Download Firmware json file from Web.")
                .short("d")
                .long("download")
        )
        .arg(
            Arg::with_name("checkjson")
                .help("Checking Firmware json file.")
                .short("j")
                .long("json")
                .takes_value(true)
                .value_name("file")
        )
        .arg(
            Arg::with_name("bootloader")
                .help("Set to bootloader mode.")
                .short("b")
                .long("bootloader")
        )
        .arg(
            Arg::with_name("flash")
                .help("Write firmware.")
                .short("f")
                .long("flash")
                .takes_value(true)
                .value_name("file")
        );

    // Parse arguments
    let matches = app.get_matches();

    println!("");
    println!("This is Nitrokey Firmware Update Tool (Non-Formula).");
    println!("This is Non-Formula.");
    println!("THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR");
    println!("IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,");
    println!("FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE");
    println!("AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER");
    println!("LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,");
    println!("OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE");
    println!("SOFTWARE.");
    println!("");
    println!("yes/no");
    let mut word = String::new();
    std::io::stdin().read_line(&mut word).ok();
    let answer = word.trim().to_string();
    if answer != "yes"{
        return Ok(());
    }

    // Start
    ctap_hid_fido2::hello();
    println!("");

    if matches.is_present("info") {
        println!("Get Firmware Information.");
        let info = nitrokey::get_version(&Cfg::init())?;
        println!("version = {}", info);
        println!("");
    }

    if matches.is_present("download") {
        println!("Please Download Firmware json file from Web.");
        println!("https://github.com/Nitrokey/nitrokey-fido2-firmware/releases/");
        println!("");
    }

    if matches.is_present("checkjson") {
        println!("Checking Firmware json file.");
        let json = matches.value_of("checkjson").unwrap().to_string();
        println!("file = {}", json);
        let _sig = check_json(&json)?;
        println!(
            "- signature({:02}) = {:?}",
            _sig.len(),
            util::to_hex_str(&_sig)
        );
        println!("Ok");
        println!("");
    }

    if matches.is_present("bootloader") {
        println!("Set to bootloader mode.");
        set_bootloader_mode()?;
        println!("");
    }

    if matches.is_present("flash") {
        println!("Write firmware.");
        let json = matches.value_of("flash").unwrap().to_string();
        let signature = check_json(&json)?;
        write_firmware(&json)?;

        println!("Verify_flash.");
        nitrokey::verify_flash(&Cfg::init(), &signature)?;
        println!("");
    }

    Ok(())
}
