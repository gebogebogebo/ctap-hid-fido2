#[allow(unused_imports)]
use crate::util;

use crate::fidokey;
use std::{thread, time};

//pub const USAGE_PAGE_FIDO: u16 = 0xf1d0;

pub const CTAP_FRAME_INIT: u8 = 0x80;
pub const PACKET_SIZE: usize = 1 + 64;
const PAYLOAD_SIZE_AN_INITIALIZATION_PACKET: usize = 64 - 7;
const PAYLOAD_SIZE_A_CONTINUATION_PACKET: usize = 64 - 5;

// CTAP Command
const CTAPHID_INIT: u8 = CTAP_FRAME_INIT | 0x06;
const CTAPHID_WINK: u8 = CTAP_FRAME_INIT | 0x08;
const CTAPHID_CBOR: u8 = CTAP_FRAME_INIT | 0x10;
//This command code is used in response messages only.
const CTAPHID_ERROR: u8 = CTAP_FRAME_INIT | 0x3F;
const CTAPHID_KEEPALIVE: u8 = CTAP_FRAME_INIT | 0x3B;
//const CTAPHID_KEEPALIVE_STATUS_PROCESSING = 1;     // The authenticator is still processing the current request.
//const CTAPHID_KEEPALIVE_STATUS_UPNEEDED = 2;       // The authenticator is waiting for user presence.

pub fn ctaphid_init(device: &fidokey::FidoKeyHid) -> Result<[u8; 4],String> {
    // CTAPHID_INIT
    let mut cmd: [u8; 65] = [0; 65];

    // Report ID
    cmd[0] = 0x00;

    // cid-dmy
    cmd[1] = 0xff;
    cmd[2] = 0xff;
    cmd[3] = 0xff;
    cmd[4] = 0xff;

    // command
    cmd[5] = CTAPHID_INIT;

    // len
    cmd[6] = 0x00;
    cmd[7] = 0x08;

    // nonce
    cmd[8] = 0xfc;
    cmd[9] = 0x8c;
    cmd[10] = 0xc9;
    cmd[11] = 0x91;
    cmd[12] = 0x14;
    cmd[13] = 0xb5;
    cmd[14] = 0x3b;
    cmd[15] = 0x12;

    //println!("CTAPHID_INIT = {}", util::to_hex_str(&cmd));

    device.write(&cmd)?;
    let buf = device.read()?;

    // CID
    Ok([buf[15], buf[16], buf[17], buf[18]])
}

fn ctaphid_cbor_responce_status(packet: &[u8]) -> (u8, u16, u8) {
    // cid
    //println!("- cid: {:?}", &packet[0..4]);
    // cmd
    //println!("- cmd: 0x{:2X}", packet[4]);

    // 応答データ全体のサイズ packet[5],[6]
    let payload_size = ((packet[5] as u16) << 8) + packet[6] as u16;
    // CTAP Status
    let response_status = packet[7];

    (packet[4], payload_size, response_status)
}

fn ctaphid_cbor_responce_get_payload_1(packet: &[u8]) -> Vec<u8> {
    (&packet[7..64]).to_vec()
}

fn ctaphid_cbor_responce_get_payload_2(packet: &[u8]) -> Vec<u8> {
    (&packet[5..64]).to_vec()
}

fn create_initialization_packet(cid: &[u8], payload: &Vec<u8>) -> (Vec<u8>, bool) {
    let mut cmd: Vec<u8> = vec![0; PACKET_SIZE];

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
    // CTAP_FRAME_INIT(0x80) | CTAPHID_CBOR (0x10)
    cmd[5] = CTAPHID_CBOR;

    // High part of payload length
    cmd[6] = (((payload.len() as u16) >> 8) as u8) & 0xff;
    // Low part of payload length
    cmd[7] = (payload.len() as u8) & 0xff;

    // payload
    let mut size = payload.len();
    let mut next = false;
    if payload.len() > PAYLOAD_SIZE_AN_INITIALIZATION_PACKET {
        size = PAYLOAD_SIZE_AN_INITIALIZATION_PACKET;
        next = true;
    }

    for counter in 0..size {
        cmd[8 + counter] = payload[counter];
    }

    (cmd, next)
}

fn create_continuation_packet(seqno: u8, cid: &[u8], payload: &Vec<u8>) -> (Vec<u8>, bool) {
    let mut cmd: Vec<u8> = vec![0; PACKET_SIZE];

    // Report ID
    cmd[0] = 0x00;

    // cid
    cmd[1] = cid[0];
    cmd[2] = cid[1];
    cmd[3] = cid[2];
    cmd[4] = cid[3];

    // seq
    cmd[5] = seqno;

    let index: usize =
        PAYLOAD_SIZE_AN_INITIALIZATION_PACKET + PAYLOAD_SIZE_A_CONTINUATION_PACKET * seqno as usize;

    // payload
    let mut size: usize = payload.len() - index;
    let mut next = false;
    if size > PAYLOAD_SIZE_A_CONTINUATION_PACKET {
        size = PAYLOAD_SIZE_A_CONTINUATION_PACKET;
        next = true;
    }

    for counter in 0..size {
        cmd[6 + counter] = payload[index + counter];
    }

    (cmd, next)
}

pub fn ctaphid_wink(device: &fidokey::FidoKeyHid, cid: &[u8]) {
    // CTAPHID_WINK
    let mut cmd: [u8; 65] = [0; 65];

    // Report ID
    cmd[0] = 0x00;

    // cid-dmy
    cmd[1] = cid[0];
    cmd[2] = cid[1];
    cmd[3] = cid[2];
    cmd[4] = cid[3];

    // command
    cmd[5] = CTAPHID_WINK;

    // len
    cmd[6] = 0x00;
    cmd[7] = 0x00;

    //println!("CTAPHID_WINK = {}", util::to_hex_str(&cmd));

    device.write(&cmd).unwrap();
    let _buf = device.read().unwrap();
}

pub fn ctaphid_cbor(
    device: &fidokey::FidoKeyHid,
    cid: &[u8],
    payload: &Vec<u8>,
) -> Result<Vec<u8>, String> {
    // initialization_packet
    let res = create_initialization_packet(cid, payload);
    //println!("CTAPHID_CBOR(0) = {}", util::to_hex_str(&res.0));

    // Write data to device
    let _res = device.write(&res.0).unwrap();
    //println!("Wrote: {:?} byte", res);

    // next
    if res.1 == true {
        for seqno in 0..100 {
            let res = create_continuation_packet(seqno, cid, payload);
            //println!("CTAPHID_CBOR(1) = {}", util::to_hex_str(&res.0));
            let _res = device.write(&res.0).unwrap();
            if res.1 == false {
                break;
            }
        }
    }

    // read - 1st packet
    let mut keep_alive_msg_flag = false;
    let mut st: (u8, u16, u8) = (0, 0, 0);
    let mut packet_1st = vec![];
    for _ in 0..100 {
        let buf = match device.read() {
            Ok(res) => res,
            Err(_error) => {
                return Err(format!(
                    "read err = {}",
                    util::get_ctap_status_message(0xfe)
                ));
            }
        };
        //println!("Read: {:?} byte", res);

        st = ctaphid_cbor_responce_status(&buf);
        if st.0 == CTAPHID_CBOR {
            packet_1st = buf;
            break;
        } else if st.0 == CTAPHID_KEEPALIVE {
            if keep_alive_msg_flag == false {
                println!("- touch fido key");
                keep_alive_msg_flag = true;
            }
            thread::sleep(time::Duration::from_millis(100));
        } else if st.0 == CTAPHID_ERROR {
            println!("CTAPHID_ERROR Error code = 0x{:02x}", st.2);
            break;
        } else {
            println!("err");
            break;
        }
    }

    let payload_size = st.1;
    let response_status = st.2;
    //println!("payload_size = {:?} byte", payload_size);
    //println!("response_status = 0x{:02X}", response_status);

    if response_status != 0x00 {
        Err(format!(
            "response_status err = {}",
            util::get_ctap_status_message(response_status)
        ))
    } else {
        let mut payload = ctaphid_cbor_responce_get_payload_1(&packet_1st);

        // 次のパケットがある?
        if (payload.len() as u16) < payload_size {
            for _ in 1..=100 {
                // read next packet
                let buf = match device.read() {
                    Ok(res) => res,
                    Err(_error) => {
                        return Err(format!(
                            "read err = {}",
                            util::get_ctap_status_message(0xfe)
                        ));
                    }
                };
                //println!("Read: {:?} byte", &buf[..res]);

                let mut p2 = ctaphid_cbor_responce_get_payload_2(&buf);

                // payloadに連結
                payload.append(&mut p2);

                // 次のパケットがある?
                if (payload.len() as u16) >= payload_size {
                    break;
                }
            }
        }

        // get CBOR
        let mut cbor_data: Vec<u8> = vec![];
        for n in 1..payload_size {
            let index: usize = n.into();
            let dat = payload[index];
            cbor_data.push(dat);
        }

        /*
        println!("");
        println!("## Cbor Data");
        println!("{}", util::to_hex_str(&cbor_data));
        println!("##");
        */

        Ok(cbor_data)
    }
}
