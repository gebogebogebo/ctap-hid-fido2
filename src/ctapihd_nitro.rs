use crate::ctaphid;
use crate::util;

use crate::fidokey::*;

// Nitrokey Custom commands between 0x40-0x7f
const CTAPHID_BOOT: u8 = ctaphid::CTAP_FRAME_INIT | 0x50;
const CTAPHID_ENTERBOOT: u8 = ctaphid::CTAP_FRAME_INIT | 0x51;
//#define CTAPHID_ENTERSTBOOT     (TYPE_INIT | 0x52)
//#define CTAPHID_REBOOT          (TYPE_INIT | 0x53)
const CTAPHID_GETRNG: u8 = ctaphid::CTAP_FRAME_INIT | 0x60;
const CTAPHID_GETVERSION: u8 = ctaphid::CTAP_FRAME_INIT | 0x61;
//#define CTAPHID_LOADKEY         (TYPE_INIT | 0x62)
// reserved for debug, not implemented except for HACKER and DEBUG_LEVEl > 0
//#define CTAPHID_PROBE           (TYPE_INIT | 0x70)
const CTAPHID_GETSTATUS: u8 = ctaphid::CTAP_FRAME_INIT | 0x71;

// Nitrokey
// GETVERSION
pub fn ctaphid_nitro_get_version(device: &FidoKeyHid, cid: &[u8]) -> Result<String, String> {
    let payload: Vec<u8> = Vec::new();
    let version = match ctaphid_nitro_send_and_response2(device, cid, CTAPHID_GETVERSION, &payload)
    {
        Ok(version) => version,
        Err(err) => return Err(err),
    };

    // version - 4byte
    if version.len() != 4 {
        return Err("Version format Error".into());
    }
    let version = format!(
        "{}.{}.{}.{}",
        version[0], version[1], version[2], version[3]
    );
    Ok(version)
}

// GETRNG
pub fn ctaphid_nitro_get_rng(
    device: &FidoKeyHid,
    cid: &[u8],
    rng_byte: u8,
) -> Result<String, String> {
    let payload: Vec<u8> = vec![rng_byte];
    let result = ctaphid_nitro_send_and_response2(device, cid, CTAPHID_GETRNG, &payload)?;
    Ok(util::to_hex_str(&result))
}

// GETSTATUS
pub fn ctaphid_nitro_get_status(device: &FidoKeyHid, cid: &[u8]) -> Result<Vec<u8>, String> {
    let payload: Vec<u8> = vec![8];
    let result = ctaphid_nitro_send_and_response2(device, cid, CTAPHID_GETSTATUS, &payload)?;
    Ok(result)
}

pub fn ctaphid_nitro_enter_boot(device: &FidoKeyHid, cid: &[u8]) -> Result<(), String> {
    let payload: Vec<u8> = Vec::new();
    ctaphid_nitro_send_and_response2(device, cid, CTAPHID_ENTERBOOT, &payload)?;
    Ok(())
}

pub fn ctaphid_nitro_boot(device: &FidoKeyHid, cid: &[u8], payload: &[u8]) -> Result<(), String> {
    let _result = ctaphid_nitro_send_and_response2(device, cid, CTAPHID_BOOT, payload)?;
    Ok(())
}

pub fn ctaphid_nitro_send_and_response2(
    device: &FidoKeyHid,
    cid: &[u8],
    command: u8,
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let buf = ctaphid::ctaphid_xxx(device, cid, command, &payload.to_vec())?;
    let st = ctaphid_cbor_response_nitro(&buf);
    if st.0 != command {
        Err("ctaphid_cbor_response_nitro".into())
    } else {
        Ok(st.1)
    }
}

fn ctaphid_cbor_response_nitro(packet: &[u8]) -> (u8, Vec<u8>) {
    // cid
    //println!("- cid: {:?}", &packet[0..4]);
    // cmd
    //println!("- cmd: 0x{:2X}", packet[4]);

    // 応答データ全体のサイズ packet[5],[6]
    let payload_size: usize = (((packet[5] as u16) << 8) + packet[6] as u16).into();

    // dataを抽出
    let data = &packet[7..7 + payload_size];

    (packet[4], data.to_vec())
}
