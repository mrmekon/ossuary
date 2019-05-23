// basic.rs
//
// Benchmark test for Ossuary data throughput
//
// Benchmarks the time to transmit and receive large quantities of data over
// an established Ossuary connection.  Data is transmitted over real TCP
// sockets.
//
#![feature(test)]
extern crate test;
use test::Bencher;
use std::thread;
use std::net::{TcpListener, TcpStream};

use ossuary::{OssuaryConnection, ConnectionType};
use ossuary::OssuaryError;
//use crate::*;

#[bench]
fn bench_test(b: &mut Bencher) {
    let server_thread = thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:9987").unwrap();
        let mut server_stream = listener.incoming().next().unwrap().unwrap();
        let auth_secret_key = &[
            0x50, 0x29, 0x04, 0x97, 0x62, 0xbd, 0xa6, 0x07,
            0x71, 0xca, 0x29, 0x14, 0xe3, 0x83, 0x19, 0x0e,
            0xa0, 0x9e, 0xd4, 0xb7, 0x1a, 0xf9, 0xc9, 0x59,
            0x3e, 0xa3, 0x1c, 0x85, 0x0f, 0xc4, 0xfa, 0xa2,
        ];
        let mut server_conn = OssuaryConnection::new(ConnectionType::UnauthenticatedServer,
                                                     Some(auth_secret_key)).unwrap();
        while server_conn.handshake_done().unwrap() == false {
            if server_conn.send_handshake(&mut server_stream).is_ok() {
                loop {
                    match server_conn.recv_handshake(&mut server_stream) {
                        Ok(_) => break,
                        Err(OssuaryError::WouldBlock(_)) => {},
                        _ => panic!("Handshake failed"),
                    }
                }
            }
        }
        println!("server handshook");
        let mut plaintext = vec!();
        let mut bytes: u64 = 0;
        let start = std::time::SystemTime::now();
        loop {
            //std::thread::sleep(std::time::Duration::from_millis(100));
            match server_conn.recv_data(&mut server_stream,
                                        &mut plaintext) {
                Ok((read, _written)) => bytes += read as u64,
                Err(OssuaryError::WouldBlock(_)) => continue,
                Err(e) => {
                    println!("server recv_data err: {:?}", e);
                    panic!("Recv failed")
                },
            }
            if plaintext == [0xde, 0xde, 0xbe, 0xbe] {
                println!("finished");
                if let Ok(dur) = start.elapsed() {
                    let t = dur.as_secs() as f64
                        + dur.subsec_nanos() as f64 * 1e-9;
                    println!("Benchmark done (recv): {} bytes in {:.2} s", bytes, t);
                    println!("{:.2} MB/s [{:.2} Mbps]",
                             bytes as f64 / 1024.0 / 1024.0 / t,
                             bytes as f64 * 8.0 / 1024.0 / 1024.0 / t);
                }
                break;
            }
            plaintext.clear();
        }
    });

    std::thread::sleep(std::time::Duration::from_millis(500));
    let mut client_stream = TcpStream::connect("127.0.0.1:9987").unwrap();
    client_stream.set_nonblocking(true).unwrap();
    let mut client_conn = OssuaryConnection::new(ConnectionType::Client, None).unwrap();
    let auth_public_key = &[
        0x20, 0x88, 0x55, 0x8e, 0xbd, 0x9b, 0x46, 0x1d,
        0xd0, 0x9d, 0xf0, 0x00, 0xda, 0xf4, 0x0f, 0x87,
        0xf7, 0x38, 0x40, 0xc5, 0x54, 0x18, 0x57, 0x60,
        0x74, 0x39, 0x3b, 0xb9, 0x70, 0xe1, 0x46, 0x98,
    ];
    let keys: Vec<&[u8]> = vec![auth_public_key];
    let _ = client_conn.add_authorized_keys(keys).unwrap();
    while client_conn.handshake_done().unwrap() == false {
        if client_conn.send_handshake(&mut client_stream).is_ok() {
            loop {
                match client_conn.recv_handshake(&mut client_stream) {
                    Ok(_) => break,
                    Err(OssuaryError::WouldBlock(_)) => {},
                    Err(e) => {
                        println!("err: {:?}", e);
                        panic!("Handshake failed")
                    },
                }
            }
        }
    }
    println!("client handshook");
    let mut client_stream = std::io::BufWriter::new(client_stream);
    let mut bytes: u64 = 0;
    let start = std::time::SystemTime::now();
    let mut plaintext: &[u8] = &[0xaa; 16384];
    b.iter(|| {
        match client_conn.send_data(&mut plaintext,
                                    &mut client_stream) {
            Ok(b) => bytes += b as u64,
            Err(OssuaryError::WouldBlock(_)) => {},
            _ => panic!("send error"),
        }
    });
    if let Ok(dur) = start.elapsed() {
        let t = dur.as_secs() as f64
            + dur.subsec_nanos() as f64 * 1e-9;
        println!("Benchmark done (xmit): {} bytes in {:.2} s", bytes, t);
        println!("{:.2} MB/s [{:.2} Mbps]",
                 bytes as f64 / 1024.0 / 1024.0 / t,
                 bytes as f64 * 8.0 / 1024.0 / 1024.0 / t);
    }
    let mut plaintext: &[u8] = &[0xde, 0xde, 0xbe, 0xbe];
    loop {
        match client_conn.send_data(&mut plaintext, &mut client_stream) {
            Ok(w) => {
                println!("wrote finish: {}", w);
                break;
            },
            Err(OssuaryError::WouldBlock(_)) => {},
            _ => panic!("Send failed"),
        }
    }

    while let Ok(w) = client_conn.flush(&mut client_stream) {
        if w == 0 {
            break;
        }
    }

    // Unwrap stream until it succeeds to force it to flush.
    let mut client_stream: Option<std::io::BufWriter<_>> = Some(client_stream);
    while let Some(s) = client_stream {
        client_stream = match s.into_inner() {
            Err(e) => {
                match e.error().kind() {
                    std::io::ErrorKind::WouldBlock => Some(e.into_inner()),
                    _ => None,
                }
            },
            _ => None,
        }
    }
    let _ = server_thread.join();
}
