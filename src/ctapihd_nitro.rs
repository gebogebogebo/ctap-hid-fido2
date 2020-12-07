use crate::ctaphid;
use crate::fidokey;
use crate::util;

// Nitrokey Custom commands between 0x40-0x7f
//#define CTAPHID_BOOT            (TYPE_INIT | 0x50)
//#define CTAPHID_ENTERBOOT       (TYPE_INIT | 0x51)
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
pub fn ctaphid_nitro_get_version(device: &fidokey::FidoKeyHid, cid: &[u8]) -> Result<String, u8> {
    let payload: Vec<u8> = Vec::new();
    let version = match ctaphid_nitro_send_and_response(device, cid, CTAPHID_GETVERSION, &payload) {
        Ok(version) => version,
        Err(err) => return Err(err),
    };

    // version - 4byte
    if version.len() != 4 {
        return Err(0x02);
    }
    let version = format!(
        "{}.{}.{}.{}",
        version[0], version[1], version[2], version[3]
    );
    Ok(version)
}

// GETRNG
pub fn ctaphid_nitro_get_rng(
    device: &fidokey::FidoKeyHid,
    cid: &[u8],
    rng_byte: u8,
) -> Result<String, u8> {
    let payload: Vec<u8> = vec![rng_byte];
    match ctaphid_nitro_send_and_response(device, cid, CTAPHID_GETRNG, &payload) {
        Ok(result) => Ok(util::to_hex_str(&result)),
        Err(err) => Err(err),
    }
}

// GETSTATUS
pub fn ctaphid_nitro_get_status(device: &fidokey::FidoKeyHid, cid: &[u8]) -> Result<Vec<u8>, u8> {
    let payload: Vec<u8> = vec![8];
    match ctaphid_nitro_send_and_response(device, cid, CTAPHID_GETSTATUS, &payload) {
        Ok(result) => Ok(result),
        Err(err) => Err(err),
    }
}

pub fn ctaphid_nitro_send_and_response(
    device: &fidokey::FidoKeyHid,
    cid: &[u8],
    command: u8,
    payload: &Vec<u8>,
) -> Result<Vec<u8>, u8> {
    let mut cmd: Vec<u8> = vec![0; ctaphid::PACKET_SIZE];

    // Report ID
    // The first byte of data must contain the Report ID.
    // For devices which only support a single report, this must be set to 0x0.
    cmd[0] = 0x00;

    // cid
    cmd[1] = cid[0];
    cmd[2] = cid[1];
    cmd[3] = cid[2];
    cmd[4] = cid[3];

    // Command identifier (bit 7 always set)
    cmd[5] = command;

    if payload.len() > 0 {
        // High part of payload length
        cmd[6] = (((payload.len() as u16) >> 8) as u8) & 0xff;
        // Low part of payload length
        cmd[7] = (payload.len() as u8) & 0xff;

        for counter in 0..payload.len() {
            cmd[8 + counter] = payload[counter];
        }
    }

    // Write data to device
    let _res = device.write(&cmd).unwrap();
    //println!("Wrote: {:?} byte", _res);

    let buf = device.read().unwrap();
    //let err = device.check_error();
    //println!("Read: {:?}", &buf[.._res]);

    /*
    println!("");
    println!("## res");
    println!("{}", util::to_hex_str(&buf[.._res]));
    println!("##");
    */

    let st = ctaphid_cbor_responce_nitro(&buf);
    if st.0 != command {
        return Err(0x01);
    }

    Ok(st.1)
}

fn ctaphid_cbor_responce_nitro(packet: &[u8]) -> (u8, Vec<u8>) {
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
