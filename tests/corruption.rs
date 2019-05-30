// corruption.rs
//
// Test cases for Ossuary handshakes with packet corruption
//
// Runs through a bunch of rounds of connection handshaking with corrupted data
// injected at known points throughout the handshake.  Verifies that the correct
// errors are raised, and that the connection either retries successfully or
// fails permanently depending on the test.
//
use ossuary::{OssuaryConnection, ConnectionType};
use ossuary::OssuaryError;

#[derive(Debug)]
enum Corruption {
    ClientKey,
    ClientNonce,
    ClientChal,
    ClientAuth,
    ClientInvalidPkt,
    ServerKey,
    ServerNonce,
    ServerAuth,
    ServerInvalidPkt,
}

#[test]
fn corruption() {
    // Corruption test tuple format:
    // (test type, loop iteration, byte offset, byte value, expected recv error, permanent)
    let corruptions = [
        // loop iteration 0: Client -> Server
        // 8 bytes network header, 8 bytes packet header, 32 bytes key, 12 bytes nonce, 32 bytes challenge
        (Corruption::ClientInvalidPkt, 0, 0, 0xaa, OssuaryError::InvalidPacket("Oversized packet".into()), true),
        (Corruption::ClientInvalidPkt, 0, 2, 0xaa, OssuaryError::InvalidPacket("Message ID does not match".into()), true),
        (Corruption::ClientInvalidPkt, 0, 3, 0xaa, OssuaryError::InvalidPacket("Message ID does not match".into()), true),
        (Corruption::ClientInvalidPkt, 0, 4, 0xaa, OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()), true),
        (Corruption::ClientKey, 0, 18, 0xaa, OssuaryError::DecryptionFailed, false),
        (Corruption::ClientNonce, 0, 50, 0xaa, OssuaryError::DecryptionFailed, false),
        (Corruption::ClientChal, 0, 64, 0xaa, OssuaryError::InvalidSignature, false),

        // loop iteration 3: Server -> Client
        // 8 bytes net header, 8 bytes packet header, 32 bytes key, 12 bytes nonce, ~150 bytes encrypted auth
        (Corruption::ServerInvalidPkt, 3, 0, 0xaa, OssuaryError::InvalidPacket("Oversized packet".into()), true),
        (Corruption::ServerInvalidPkt, 3, 2, 0xaa, OssuaryError::InvalidPacket("Message ID does not match".into()), true),
        (Corruption::ServerInvalidPkt, 3, 4, 0xaa, OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()), true),
        (Corruption::ServerKey, 3, 18, 0xaa, OssuaryError::DecryptionFailed, false),
        (Corruption::ServerNonce, 3, 50, 0xaa, OssuaryError::DecryptionFailed, false),
        (Corruption::ServerAuth, 3, 64, 0xaa, OssuaryError::DecryptionFailed, false),
        (Corruption::ServerAuth, 3, 84, 0xaa, OssuaryError::DecryptionFailed, false),

        // loop iteration 2: Client -> Server
        // 8 bytes net header, 8 bytes packet header, 4 byte encryption packet, ~120 bytes encrypted auth
        (Corruption::ClientInvalidPkt, 6, 18, 0xaa, OssuaryError::InvalidPacket("Invalid packet length".into()), false),
        (Corruption::ClientAuth, 6, 24, 0xaa, OssuaryError::DecryptionFailed, false),
        (Corruption::ClientAuth, 6, 96, 0xaa, OssuaryError::DecryptionFailed, false),
    ];

    #[derive(Debug)]
    enum LoopConn {
        LoopClient,
        LoopServer,
    };

    for corruption in &corruptions {
        println!("Corruption test: {:?}", corruption.0);
        let server_secret_key = &[
            0x50, 0x29, 0x04, 0x97, 0x62, 0xbd, 0xa6, 0x07,
            0x71, 0xca, 0x29, 0x14, 0xe3, 0x83, 0x19, 0x0e,
            0xa0, 0x9e, 0xd4, 0xb7, 0x1a, 0xf9, 0xc9, 0x59,
            0x3e, 0xa3, 0x1c, 0x85, 0x0f, 0xc4, 0xfa, 0xa2,
        ];
        let server_public_key = &[
            0x20, 0x88, 0x55, 0x8e, 0xbd, 0x9b, 0x46, 0x1d,
            0xd0, 0x9d, 0xf0, 0x00, 0xda, 0xf4, 0x0f, 0x87,
            0xf7, 0x38, 0x40, 0xc5, 0x54, 0x18, 0x57, 0x60,
            0x74, 0x39, 0x3b, 0xb9, 0x70, 0xe1, 0x46, 0x98,
        ];
        let pubkeys: Vec<&[u8]> = vec![server_public_key];
        let mut server_conn = OssuaryConnection::new(ConnectionType::UnauthenticatedServer, Some(server_secret_key)).unwrap();
        let mut client_conn = OssuaryConnection::new(ConnectionType::Client, None).unwrap();
        let _ = client_conn.add_authorized_keys(pubkeys).unwrap();

        let mut loop_conn = LoopConn::LoopClient;
        let mut client_buf: Vec<u8> = vec!();
        let mut server_buf: Vec<u8> = vec!();
        let mut loop_count = 0;

        loop {
            let mut done = 0;
            let (send_conn, recv_conn, mut send_buf, recv_buf) = match loop_conn {
                LoopConn::LoopClient => (&mut client_conn, &mut server_conn, &mut client_buf, &mut server_buf),
                _ => (&mut server_conn, &mut client_conn, &mut server_buf, &mut client_buf),
            };
            match send_conn.handshake_done() {
                Ok(true) => done += 1,
                Ok(false) => {},
                Err(OssuaryError::ConnectionFailed) => {
                    match corruption.5 {
                        true => break,
                        false => panic!("Unexpected connection failure."),
                    }
                }
                Err(e) => match e {
                    ref e if e == &corruption.4 => {}, // expected error
                    OssuaryError::ConnectionFailed => {
                        match corruption.5 {
                            true => break,
                            false => panic!("Unexpected connection failure."),
                        }
                    },
                    OssuaryError::ConnectionReset(b) => { recv_buf.drain(0..b); },
                    _ => panic!("Handshake failed: {:?}", e),
                },
            }
            match recv_conn.handshake_done() {
                Ok(true) => done += 1,
                Ok(false) => {},
                Err(OssuaryError::ConnectionFailed) => {
                    match corruption.5 {
                        true => break,
                        false => panic!("Unexpected connection failure."),
                    }
                }
                Err(e) => match e {
                    ref e if e == &corruption.4 => {}, // expected error
                    OssuaryError::ConnectionFailed => {
                        match corruption.5 {
                            true => break,
                            false => panic!("Unexpected connection failure."),
                        }
                    },
                    OssuaryError::ConnectionReset(b) => { recv_buf.drain(0..b); },
                    _ => panic!("Handshake failed: {:?}", e),
                },
            }
            if done == 2 {
                break;
            }
            send_conn.send_handshake(&mut send_buf).unwrap();
            if send_buf.len() > 0 {
                //println!("{:?}({}) {:?}", loop_conn, loop_count, send_buf);
            }
            if loop_count == corruption.1 {
                send_buf[corruption.2] = corruption.3;
            }
            match send_conn.recv_handshake(&mut recv_buf.as_slice()) {
                Ok(b) => { recv_buf.drain(0..b); },
                Err(OssuaryError::WouldBlock(b)) => { recv_buf.drain(0..b); },
                Err(e) => match e {
                    ref e if e == &corruption.4 => {}, // expected error
                    OssuaryError::ConnectionFailed => {
                        match corruption.5 {
                            true => break,
                            false => panic!("Unexpected connection failure."),
                        }
                    },
                    OssuaryError::ConnectionReset(b) => { recv_buf.drain(0..b); },
                    _ => panic!("Handshake failed: {:?}", e),
                },
            }
            // Check if handshake is done and call recv_data because recv_handshake()
            // does not respond to connection resets after the connection is (thought
            // to be) established.
            match send_conn.handshake_done() {
                Ok(true) => {
                    let mut plaintext = Vec::<u8>::new();
                    match send_conn.recv_data(&mut recv_buf.as_slice(), &mut plaintext) {
                        Ok((b,_)) => { recv_buf.drain(0..b); },
                        Err(OssuaryError::WouldBlock(b)) => { recv_buf.drain(0..b); },
                        Err(e) => match e {
                            ref e if e == &corruption.4 => {}, // expected error
                            OssuaryError::ConnectionFailed => {
                                match corruption.5 {
                                    true => break,
                                    false => panic!("Unexpected connection failure."),
                                }
                            },
                            OssuaryError::ConnectionReset(b) => { recv_buf.drain(0..b); },
                            _ => panic!("Handshake failed: {:?}", e),
                        },
                    }
                },
                //Err(e) => panic!("ERROR: {:?}", e),
                Err(e) => match e {
                    ref e if e == &corruption.4 => {}, // expected error
                    OssuaryError::ConnectionFailed => {
                        match corruption.5 {
                            true => break,
                            false => panic!("Unexpected connection failure."),
                        }
                    },
                    OssuaryError::ConnectionReset(b) => { recv_buf.drain(0..b); },
                    _ => panic!("Handshake failed: {:?}", e),
                },
                _ => {},
            }
            loop_conn = match loop_conn {
                LoopConn::LoopClient => LoopConn::LoopServer,
                _ => LoopConn::LoopClient,
            };
            loop_count += 1;
        }
    }
}
