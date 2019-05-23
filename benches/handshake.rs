// handshake.rs
//
// Benchmark test for Ossuary handshakes
//
// Benchmarks the time to perform the handshake dance until both sides are
// connected successfully.  Data transferred in local buffers, no network.
//
#![feature(test)]
extern crate test;
use test::Bencher;

use ossuary::{OssuaryConnection, ConnectionType};
use ossuary::OssuaryError;

#[derive(Debug)]
enum LoopConn {
    LoopClient,
    LoopServer,
}

#[bench]
fn bench_handshake(b: &mut Bencher) {
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
    let mut loop_conn = LoopConn::LoopClient;
    let mut client_buf: Vec<u8> = vec!();
    let mut server_buf: Vec<u8> = vec!();

    let mut iters: usize = 0;
    let start = std::time::SystemTime::now();
    b.iter(|| {
        let mut server_conn = OssuaryConnection::new(ConnectionType::UnauthenticatedServer, Some(&server_secret_key.clone())).unwrap();
        let mut client_conn = OssuaryConnection::new(ConnectionType::Client, None).unwrap();
        let key_slice: &[u8] = server_public_key;
        let _ = client_conn.add_authorized_key(key_slice).unwrap();
        loop {
            let mut done = 0;
            let (send_conn, recv_conn, mut send_buf, recv_buf) = match loop_conn {
                LoopConn::LoopClient => (&mut client_conn, &mut server_conn, &mut client_buf, &mut server_buf),
                _ => (&mut server_conn, &mut client_conn, &mut server_buf, &mut client_buf),
            };
            match send_conn.handshake_done() {
                Ok(true) => done += 1,
                Ok(false) => {},
                Err(e) => panic!("handshake failed: {:?}", e),
            }
            match recv_conn.handshake_done() {
                Ok(true) => done += 1,
                Ok(false) => {},
                Err(e) => panic!("handshake failed: {:?}", e),
            }
            if done == 2 {
                iters += 1;
                break;
            }
            send_conn.send_handshake(&mut send_buf).unwrap();
            match send_conn.recv_handshake(&mut recv_buf.as_slice()) {
                Ok(b) => { recv_buf.drain(0..b); },
                Err(OssuaryError::WouldBlock(b)) => { recv_buf.drain(0..b); },
                _ => panic!("handshake failed"),
            }
            loop_conn = match loop_conn {
                LoopConn::LoopClient => LoopConn::LoopServer,
                _ => LoopConn::LoopClient,
            };
        }
    });
    if let Ok(dur) = start.elapsed() {
        let t = dur.as_secs() as f64
            + dur.subsec_nanos() as f64 * 1e-9;
        println!("Benchmark done: {} handshakes in {:.2} s", iters, t);
        println!("{:.2} shakes/s", iters as f64 / t);
    }
}
