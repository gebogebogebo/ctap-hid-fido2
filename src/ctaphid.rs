use crate::{ctapdef, fidokey::FidoKeyHid, util};
#[cfg(feature = "tokio")]#[cfg(feature = "tokio")]use crate::fidokey::FidoKeyHidAsync;
use anyhow::{anyhow, Error, Result};
use std::{thread, time};
use rand::{rng, Rng};

//pub const USAGE_PAGE_FIDO: u16 = 0xf1d0;

pub const CTAP_FRAME_INIT: u8 = 0x80;
pub const PACKET_SIZE: usize = 1 + 64;
const PAYLOAD_SIZE_AN_INITIALIZATION_PACKET: usize = 64 - 7;
const PAYLOAD_SIZE_A_CONTINUATION_PACKET: usize = 64 - 5;

// CTAPHID Command
const CTAPHID_MSG: u8 = CTAP_FRAME_INIT | 0x03;
const CTAPHID_INIT: u8 = CTAP_FRAME_INIT | 0x06;
const CTAPHID_WINK: u8 = CTAP_FRAME_INIT | 0x08;
const CTAPHID_CBOR: u8 = CTAP_FRAME_INIT | 0x10;
const CTAPHID_CANCEL: u8 = CTAP_FRAME_INIT | 0x11;
//This command code is used in response messages only.
const CTAPHID_ERROR: u8 = CTAP_FRAME_INIT | 0x3F;
const CTAPHID_KEEPALIVE: u8 = CTAP_FRAME_INIT | 0x3B;

//const CTAPHID_KEEPALIVE_STATUS_PROCESSING = 1;     // The authenticator is still processing the current request.
//const CTAPHID_KEEPALIVE_STATUS_UPNEEDED = 2;       // The authenticator is waiting for user presence.

// Function to generate random nonce
fn generate_random_nonce() -> [u8; 8] {
    let mut rng = rng();
    let mut nonce = [0u8; 8];
    rng.fill(&mut nonce);
    nonce
}

pub fn ctaphid_init(device: &FidoKeyHid) -> Result<[u8; 4]> {
    // Generate random nonce
    let nonce = generate_random_nonce();
    
    // CTAPHID_INIT
    let cmd = ctaphid_init_cmd(&nonce);

    if device.enable_log {
        println!("CTAPHID_INIT = {}", util::to_hex_str(&cmd));
    }

    device.write(&cmd).map_err(Error::msg)?;
    let buf = device.read().map_err(Error::msg)?;

    if device.enable_log {
        println!("CTAPHID_INIT response = {}", util::to_hex_str(&buf));
    }

    let cid = validate_and_get_cid(device.enable_log, &nonce, &buf)?;

    if device.enable_log {
        println!("CID: {}", util::to_hex_str(&cid));
    }

    // Return the dynamically adjusted CID
    Ok(cid)
}

#[cfg(feature = "tokio")]pub async fn ctaphid_init_async(device: &FidoKeyHidAsync) -> Result<[u8; 4]> {
    // Generate random nonce
    let nonce = generate_random_nonce();
    
    // CTAPHID_INIT
    let cmd = ctaphid_init_cmd(&nonce);

    if device.enable_log {
        println!("CTAPHID_INIT = {}", util::to_hex_str(&cmd));
    }

    device.write(&cmd).await.map_err(Error::msg)?;
    let buf = device.read().await.map_err(Error::msg)?;

    if device.enable_log {
        println!("CTAPHID_INIT response = {}", util::to_hex_str(&buf));
    }

    let cid = validate_and_get_cid(device.enable_log, &nonce, &buf)?;

    if device.enable_log {
        println!("CID: {}", util::to_hex_str(&cid));
    }

    // Return the dynamically adjusted CID
    Ok(cid)
}

fn ctaphid_init_cmd(nonce: &[u8; 8]) -> [u8; 65] {
    // CTAPHID_INIT
    let mut cmd: [u8; 65] = [0; 65];

    // Report ID
    cmd[0] = 0x00;

    // cid-dmy (broadcast channel ID)
    cmd[1] = 0xff;
    cmd[2] = 0xff;
    cmd[3] = 0xff;
    cmd[4] = 0xff;

    // command
    cmd[5] = CTAPHID_INIT;

    // len
    cmd[6] = 0x00;
    cmd[7] = 0x08;

    // Add random nonce
    cmd[8..16].copy_from_slice(nonce);

    // Return cmd
    cmd
}

fn validate_and_get_cid(enable_log: bool, nonce: &[u8; 8], buf: &Vec<u8>) -> Result<[u8; 4]> {
    // Check if the received buffer includes Report ID (0x00)
    let has_report_id = buf.len() == 65 && buf[0] == 0x00;
    // Determine the starting offset for the data section (nonce start)
    let data_offset = if has_report_id { 8 } else { 7 };

    // Extract and verify nonce from the response
    let response_nonce = &buf[data_offset..data_offset + 8];
    
    if enable_log {
        println!("=== NONCE INFO ===");
        println!("SENT NONCE: {}", util::to_hex_str(nonce));
        println!("RECV NONCE: {}", util::to_hex_str(response_nonce));
    }
    
    if nonce != response_nonce {
        return Err(anyhow!("Nonce verification failed"));
    }

    // CID follows immediately after the nonce
    let cid_offset = data_offset + 8;
    Ok([
        buf[cid_offset],
        buf[cid_offset + 1],
        buf[cid_offset + 2],
        buf[cid_offset + 3],
    ])
}

fn get_responce_status(packet: &[u8]) -> Result<(u8, u16, u8)> {
    // cid
    //println!("- cid: {:?}", &packet[0..4]);
    // cmd
    //println!("- cmd: 0x{:2X}", packet[4]);

    let command = packet[4];

    // response size
    let payload_size = ((packet[5] as u16) << 8) + packet[6] as u16;

    // status
    let response_status = if command == CTAPHID_MSG {
        // length check ()
        if payload_size > packet.len() as u16 {
            return Err(anyhow!("u2f response size error?"));
        }
        // U2F(last byte of data)
        packet[(4 + 2 + payload_size - 1) as usize]
    } else {
        // CTAP(first byte of data)
        packet[7]
    };

    Ok((command, payload_size, response_status))
}

fn is_responce_error(status: (u8, u16, u8)) -> bool {
    if status.0 == CTAPHID_MSG {
        status.2 != 0x90
    } else {
        status.2 != 0x00
    }
}

fn get_status_message(status: (u8, u16, u8)) -> String {
    if status.0 == CTAPHID_MSG {
        ctapdef::get_u2f_status_message(status.2)
    } else {
        ctapdef::get_ctap_status_message(status.2)
    }
}

fn get_data(status: (u8, u16, u8), payload: Vec<u8>) -> Vec<u8> {
    let statindex = if status.0 == CTAPHID_MSG { 0 } else { 1 };

    // data size
    let datasize = if status.0 == CTAPHID_MSG {
        // remove SW1 , SW2
        status.1 - 2
    } else {
        status.1
    };

    // get CBOR
    let mut data: Vec<u8> = vec![];
    for n in statindex..datasize {
        let index: usize = n.into();
        let dat = payload[index];
        data.push(dat);
    }
    data
}

fn ctaphid_cbor_responce_get_payload_1(packet: &[u8]) -> Vec<u8> {
    packet[7..64].to_vec()
}

fn ctaphid_cbor_responce_get_payload_2(packet: &[u8]) -> Vec<u8> {
    packet[5..64].to_vec()
}

fn create_initialization_packet(cid: &[u8], commoand: u8, payload: &[u8]) -> (Vec<u8>, bool) {
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
    // ex. CTAP_FRAME_INIT(0x80) | CTAPHID_CBOR (0x10)
    cmd[5] = commoand;

    // High part of payload length
    cmd[6] = ((payload.len() as u16) >> 8) as u8;
    // Low part of payload length
    cmd[7] = payload.len() as u8;

    // payload
    let mut size = payload.len();
    let mut next = false;
    if payload.len() > PAYLOAD_SIZE_AN_INITIALIZATION_PACKET {
        size = PAYLOAD_SIZE_AN_INITIALIZATION_PACKET;
        next = true;
    }

    cmd[8..(size + 8)].clone_from_slice(&payload[..size]);

    (cmd, next)
}

fn create_continuation_packet(seqno: u8, cid: &[u8], payload: &[u8]) -> (Vec<u8>, bool) {
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
        PAYLOAD_SIZE_AN_INITIALIZATION_PACKET + PAYLOAD_SIZE_A_CONTINUATION_PACKET * (seqno as usize);

    // payload
    let mut size: usize = payload.len() - index;
    let mut next = false;
    if size > PAYLOAD_SIZE_A_CONTINUATION_PACKET {
        size = PAYLOAD_SIZE_A_CONTINUATION_PACKET;
        next = true;
    }

    cmd[6..(size + 6)].clone_from_slice(&payload[index..(size + index)]);
    (cmd, next)
}

pub fn ctaphid_wink(device: &FidoKeyHid) -> Result<()> {
    // CTAPHID_WINK
    let cmd = ctaphid_wink_cmd(device.get_cid()?);

    if device.enable_log {
        println!("- wink({:02})    = {:?}", cmd.len(), util::to_hex_str(&cmd));
    }

    device.write(&cmd).map_err(Error::msg)?;

    let _buf = device.read().map_err(Error::msg)?;

    if device.enable_log {
        println!(
            "- response wink({:02})    = {:?}",
            _buf.len(),
            util::to_hex_str(&_buf)
        );
    }

    Ok(())
}

#[cfg(feature = "tokio")]pub async fn ctaphid_wink_async(device: &FidoKeyHidAsync) -> Result<()> {
    // CTAPHID_WINK
    let cmd = ctaphid_wink_cmd(device.get_cid().await?);

    if device.enable_log {
        println!("- wink({:02})    = {:?}", cmd.len(), util::to_hex_str(&cmd));
    }

    device.write(&cmd).await.map_err(Error::msg)?;

    let _buf = device.read().await.map_err(Error::msg)?;

    if device.enable_log {
        println!(
            "- response wink({:02})    = {:?}",
            _buf.len(),
            util::to_hex_str(&_buf)
        );
    }

    Ok(())
}

fn ctaphid_wink_cmd(cid: [u8; 4]) -> [u8; 65] {
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

    cmd
}

pub fn ctaphid_cancel(device: &FidoKeyHid) -> Result<()> {
    // CTAPHID_CANCEL
    let cmd = ctaphid_cancel_cmd(device.get_cid()?);

    if device.enable_log {
        println!("CTAPHID_CANCEL = {}", util::to_hex_str(&cmd));
    }

    device.write(&cmd).map_err(Error::msg)?;
    // Cancel command may not return a response or may return an error if no operation to cancel.
    // For now, we don't expect a specific response, just that the command was sent.
    // If a response is read here, it might block indefinitely if the authenticator doesn't send one.
    Ok(())
}

#[cfg(feature = "tokio")]pub async fn ctaphid_cancel_async(device: &FidoKeyHidAsync) -> Result<()> {
    // CTAPHID_CANCEL
    let cmd = ctaphid_cancel_cmd(device.get_cid().await?);

    if device.enable_log {
        println!("CTAPHID_CANCEL = {}", util::to_hex_str(&cmd));
    }

    device.write(&cmd).await.map_err(Error::msg)?;
    // Cancel command may not return a response or may return an error if no operation to cancel.
    // For now, we don't expect a specific response, just that the command was sent.
    // If a response is read here, it might block indefinitely if the authenticator doesn't send one.
    Ok(())
}

fn ctaphid_cancel_cmd(cid: [u8; 4]) -> [u8; 65] {
    // CTAPHID_CANCEL
    let mut cmd: [u8; 65] = [0; 65];

    // Report ID
    cmd[0] = 0x00;

    // cid
    cmd[1] = cid[0];
    cmd[2] = cid[1];
    cmd[3] = cid[2];
    cmd[4] = cid[3];

    // command
    cmd[5] = CTAPHID_CANCEL;

    // len (0)
    cmd[6] = 0x00;
    cmd[7] = 0x00;

    cmd
}

fn ctaphid_cbormsg(
    device: &FidoKeyHid,
    command: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if device.enable_log {
        println!();
        println!("-- send cbor({:02})", payload.len());
        println!("{}", util::to_hex_str(payload));
        println!("--");
    }

    // Get CID
    let cid = device.get_cid()?;

    // initialization_packet
    let res = create_initialization_packet(&cid, command, payload);
    //println!("CTAPHID_CBOR(0) = {}", util::to_hex_str(&res.0));

    // Write data to device
    let _res = device.write(&res.0).map_err(Error::msg)?;
    //println!("Wrote: {:?} byte", res);

    // next
    if res.1 {
        for seqno in 0..100 {
            let res = create_continuation_packet(seqno, &cid, payload);
            //println!("CTAPHID_CBOR(1) = {}", util::to_hex_str(&res.0));
            let _res = device.write(&res.0).map_err(Error::msg)?;
            if !res.1 {
                break;
            }
        }
    }

    // read - 1st packet
    let mut keep_alive_msg_flag = false;
    let mut st: (u8, u16, u8) = (0, 0, 0);
    let mut packet_1st = vec![];
    for _counter in 0..500 {
        // println!("counter: {:?}", _counter);

        let buf = match device.read() {
            Ok(res) => res,
            Err(_error) => {
                let msg = format!("read err = {}", ctapdef::get_ctap_status_message(0xfe));
                return Err(anyhow!(msg));
            }
        };
        //println!("Read: {:?} byte", res);

        if command != CTAPHID_CBOR && command != CTAPHID_MSG {
            return Ok(buf);
        }

        st = get_responce_status(&buf)?;
        if st.0 == CTAPHID_CBOR || st.0 == CTAPHID_MSG {
            packet_1st = buf;
            break;
        } else if st.0 == CTAPHID_KEEPALIVE {
            if !keep_alive_msg_flag {
                if !device.keep_alive_msg.is_empty() {
                    println!("{}", device.keep_alive_msg);
                }
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

    //println!("payload_size = {:?} byte", payload_size);
    //println!("response_status = 0x{:02X}", st.2);

    if is_responce_error(st) {
        Err(anyhow!(format!(
            "response_status err = {}",
            get_status_message(st)
        )))
    } else {
        let mut payload = ctaphid_cbor_responce_get_payload_1(&packet_1st);

        // Is Exists Next Packet?
        let payload_size = st.1;
        if (payload.len() as u16) < payload_size {
            for _ in 1..=100 {
                // read next packet
                let buf = match device.read() {
                    Ok(res) => res,
                    Err(_error) => {
                        let msg = format!("read err = {}", ctapdef::get_ctap_status_message(0xfe));
                        return Err(anyhow!(msg));
                    }
                };
                //println!("Read: {:?} byte", &buf[..res]);

                let mut p2 = ctaphid_cbor_responce_get_payload_2(&buf);

                // Append to payload
                payload.append(&mut p2);

                // Is there another packet?
                if (payload.len() as u16) >= payload_size {
                    break;
                }
            }
        }

        // get data
        let data = get_data(st, payload);

        if device.enable_log {
            println!();
            println!("## response cbor({:02})", data.len());
            println!("{}", util::to_hex_str(&data));
            println!("##");
        }

        Ok(data)
    }
}

#[cfg(feature = "tokio")]async fn ctaphid_cbormsg_async(
    device: &FidoKeyHidAsync,
    command: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    if device.enable_log {
        println!();
        println!("-- send cbor({:02})", payload.len());
        println!("{}", util::to_hex_str(payload));
        println!("--");
    }

    // Get CID
    let cid = device.get_cid().await?;

    // initialization_packet
    let res = create_initialization_packet(&cid, command, payload);

    //println!("CTAPHID_CBOR(0) = {}", util::to_hex_str(&res.0));

    // Write data to device
    let _res = device.write(&res.0).await.map_err(Error::msg)?;
    //println!("Wrote: {:?} byte", res);

    // next
    if res.1 {
        for seqno in 0..100 {
            let res = create_continuation_packet(seqno, &cid, payload);
            //println!("CTAPHID_CBOR(1) = {}", util::to_hex_str(&res.0));
            let _res = device.write(&res.0).await.map_err(Error::msg)?;
            if !res.1 {
                break;
            }
        }
    }

    // read - 1st packet
    let mut keep_alive_msg_flag = false;
    let mut st: (u8, u16, u8) = (0, 0, 0);
    let mut packet_1st = vec![];
    for _counter in 0..500 {
        // println!("counter: {:?}", _counter);

        let buf = match device.read().await {
            Ok(res) => res,
            Err(_error) => {
                let msg = format!("read err = {}", ctapdef::get_ctap_status_message(0xfe));
                return Err(anyhow!(msg));
            }
        };
        //println!("Read: {:?} byte", res);

        if command != CTAPHID_CBOR && command != CTAPHID_MSG {
            return Ok(buf);
        }

        st = get_responce_status(&buf)?;
        if st.0 == CTAPHID_CBOR || st.0 == CTAPHID_MSG {
            packet_1st = buf;
            break;
        } else if st.0 == CTAPHID_KEEPALIVE {
            if !keep_alive_msg_flag {
                if !device.keep_alive_msg.is_empty() {
                    println!("{}", device.keep_alive_msg);
                }
                keep_alive_msg_flag = true;
            }
            tokio::time::sleep(time::Duration::from_millis(100)).await;
        } else if st.0 == CTAPHID_ERROR {
            println!("CTAPHID_ERROR Error code = 0x{:02x}", st.2);
            break;
        } else {
            println!("err");
            break;
        }
    }

    //println!("payload_size = {:?} byte", payload_size);
    //println!("response_status = 0x{:02X}", st.2);

    if is_responce_error(st) {
        Err(anyhow!(format!(
            "response_status err = {}",
            get_status_message(st)
        )))
    } else {
        let mut payload = ctaphid_cbor_responce_get_payload_1(&packet_1st);

        // Is Exists Next Packet?
        let payload_size = st.1;
        if (payload.len() as u16) < payload_size {
            for _ in 1..=100 {
                // read next packet
                let buf = match device.read().await {
                    Ok(res) => res,
                    Err(_error) => {
                        let msg = format!("read err = {}", ctapdef::get_ctap_status_message(0xfe));
                        return Err(anyhow!(msg));
                    }
                };
                //println!("Read: {:?} byte", &buf[..res]);

                let mut p2 = ctaphid_cbor_responce_get_payload_2(&buf);

                // Append to payload
                payload.append(&mut p2);

                // Is there another packet?
                if (payload.len() as u16) >= payload_size {
                    break;
                }
            }
        }

        // get data
        let data = get_data(st, payload);

        if device.enable_log {
            println!();
            println!("## response cbor({:02})", data.len());
            println!("{}", util::to_hex_str(&data));
            println!("##");
        }

        Ok(data)
    }
}

pub fn ctaphid_cbor(device: &FidoKeyHid, payload: &[u8]) -> Result<Vec<u8>> {
    ctaphid_cbormsg(device, CTAPHID_CBOR, payload)
}

#[cfg(feature = "tokio")]pub async fn ctaphid_cbor_async(device: &FidoKeyHidAsync, payload: &[u8]) -> Result<Vec<u8>> {
    ctaphid_cbormsg_async(device, CTAPHID_CBOR, payload).await
}

pub fn ctaphid_msg(device: &FidoKeyHid, payload: &[u8]) -> Result<Vec<u8>> {
    ctaphid_cbormsg(device, CTAPHID_MSG, payload)
}

#[cfg(feature = "tokio")]pub async fn ctaphid_msg_async(device: &FidoKeyHidAsync, payload: &[u8]) -> Result<Vec<u8>> {
    ctaphid_cbormsg_async(device, CTAPHID_MSG, payload).await
}

pub fn send_apdu(
    device: &FidoKeyHid,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Result<Vec<u8>> {
    /*
    Packs and sends an APDU for use in CTAP1 commands.
    This is a low-level method mainly used internally. Avoid calling it
    directly if possible, and use the get_version, register, and
    authenticate methods if possible instead.
    :param cla: The CLA parameter of the request.
    :param ins: The INS parameter of the request.
    :param p1: The P1 parameter of the request.
    :param p2: The P2 parameter of the request.
    :param data: The body of the request.
    :return: The response APDU data of a successful request.
    :raise: ApduError
    */

    let mut apdu: Vec<u8> = vec![0; 7 + data.len()];
    // reserved
    apdu[0] = cla;
    // U2F Command
    apdu[1] = ins;
    // param-1
    apdu[2] = p1;
    // param-2
    apdu[3] = p2;

    // data-len(3byte)
    apdu[4] = 0;
    // High part of payload length
    apdu[5] = ((data.len() as u16) >> 8) as u8;
    // Low part of payload length
    apdu[6] = data.len() as u8;

    // data
    let size = data.len();
    apdu[7..(size + 7)].clone_from_slice(&data[..size]);

    ctaphid_msg(device, &apdu)
}

#[cfg(feature = "tokio")]pub async fn send_apdu_async(
    device: &FidoKeyHidAsync,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: &[u8],
) -> Result<Vec<u8>> {
    /*
    Packs and sends an APDU for use in CTAP1 commands.
    This is a low-level method mainly used internally. Avoid calling it
    directly if possible, and use the get_version, register, and
    authenticate methods if possible instead.
    :param cla: The CLA parameter of the request.
    :param ins: The INS parameter of the request.
    :param p1: The P1 parameter of the request.
    :param p2: The P2 parameter of the request.
    :param data: The body of the request.
    :return: The response APDU data of a successful request.
    :raise: ApduError
    */

    let mut apdu: Vec<u8> = vec![0; 7 + data.len()];
    // reserved
    apdu[0] = cla;
    // U2F Command
    apdu[1] = ins;
    // param-1
    apdu[2] = p1;
    // param-2
    apdu[3] = p2;

    // data-len(3byte)
    apdu[4] = 0;
    // High part of payload length
    apdu[5] = ((data.len() as u16) >> 8) as u8;
    // Low part of payload length
    apdu[6] = data.len() as u8;

    // data
    let size = data.len();
    apdu[7..(size + 7)].clone_from_slice(&data[..size]);

    ctaphid_msg_async(device, &apdu).await
}

/*
https://github.com/Yubico/python-fido2/blob/master/fido2/ctap1.py#L214
    def send_apdu(self, cla=0, ins=0, p1=0, p2=0, data=b""):
        """Packs and sends an APDU for use in CTAP1 commands.
        This is a low-level method mainly used internally. Avoid calling it
        directly if possible, and use the get_version, register, and
        authenticate methods if possible instead.
        :param cla: The CLA parameter of the request.
        :param ins: The INS parameter of the request.
        :param p1: The P1 parameter of the request.
        :param p2: The P2 parameter of the request.
        :param data: The body of the request.
        :return: The response APDU data of a successful request.
        :raise: ApduError
        """
        apdu = struct.pack(">BBBBBH", cla, ins, p1, p2, 0, len(data)) + data + b"\0\0"

        response = self.device.call(CTAPHID.MSG, apdu)
        status = struct.unpack(">H", response[-2:])[0]
        data = response[:-2]
        if status != APDU.OK:
            raise ApduError(status, data)
        return data
*/
