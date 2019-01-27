#![feature(test)]
extern crate test;
use test::Bencher;
use std::thread;
use std::net::{TcpListener, TcpStream};

use ossuary::{OssuaryContext, ConnectionType};
use ossuary::OssuaryError;
//use crate::*;

#[bench]
fn bench_test(b: &mut Bencher) {
    let server_thread = thread::spawn(move || {
        let listener = TcpListener::bind("127.0.0.1:9987").unwrap();
        let mut server_stream = listener.incoming().next().unwrap().unwrap();
        let mut server_conn = OssuaryContext::new(ConnectionType::UnauthenticatedServer);
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
                    println!("err: {:?}", e);
                    panic!("Recv failed")
                },
            }
            if plaintext == [0xde, 0xde, 0xbe, 0xbe] {
                println!("finished");
                if let Ok(dur) = start.elapsed() {
                    let t = dur.as_secs() as f64
                        + dur.subsec_nanos() as f64 * 1e-9;
                    println!("Benchmark done (recv): {} bytes in {:.2} s", bytes, t);
                    println!("{:.2} MB/s", bytes as f64 / 1024.0 / 1024.0 / t);
                }
                break;
            }
            plaintext.clear();
        }
    });

    std::thread::sleep(std::time::Duration::from_millis(500));
    let mut client_stream = TcpStream::connect("127.0.0.1:9987").unwrap();
    client_stream.set_nonblocking(true).unwrap();
    let mut client_conn = OssuaryContext::new(ConnectionType::Client);
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
        println!("{:.2} MB/s", bytes as f64 / 1024.0 / 1024.0 / t);
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
