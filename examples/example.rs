// example.rs
//
// Basic example of Ossuary communication library, without authentication
//
// Establishes a non-authenticated session between a client and server over a
// TCP connection, and exchanges encrypted messages.
//
use ossuary::{OssuaryConnection, ConnectionType};
use ossuary::OssuaryError;

use std::thread;
use std::net::{TcpListener, TcpStream};

fn event_loop(mut conn: OssuaryConnection,
              mut stream: TcpStream,
              is_server: bool) -> Result<(), std::io::Error> {
    let mut strings = vec!("message1", "message2", "message3");
    let mut plaintext = Vec::<u8>::new();
    let start = std::time::Instant::now();

    // Simply run for 2 seconds
    while start.elapsed().as_secs() < 2 {
        match conn.handshake_done() {
            // Handshaking
            Ok(false) => {
                conn.send_handshake(&mut stream).expect("handshake failed");
                conn.recv_handshake(&mut stream).expect("handshake failed");
            },
            // Transmitting on encrypted connection
            Ok(true) => {
                if let Some(plaintext) = strings.pop() {
                    let _ = conn.send_data(plaintext.as_bytes(), &mut stream);
                }
                if let Ok(_) =  conn.recv_data(&mut stream, &mut plaintext) {
                    println!("({}) received: {:?}", is_server,
                             String::from_utf8(plaintext.clone()).unwrap());
                    plaintext.clear();
                }
            },
            // Trust-On-First-Use
            Err(OssuaryError::UntrustedServer(pubkey)) => {
                let keys: Vec<&[u8]> = vec![&pubkey];
                let _ = conn.add_authorized_keys(keys).unwrap();
            }
            // Uh-oh.
            Err(e) => panic!("Handshake failed with error: {:?}", e),
        }
    }
    Ok(())
}

fn server() -> Result<(), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:9988").unwrap();
    let stream: TcpStream = listener.incoming().next().unwrap().unwrap();
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(100u64)));
    // This server lets any client connect
    let conn = OssuaryConnection::new(ConnectionType::UnauthenticatedServer, None).unwrap();
    let _ = event_loop(conn, stream, true);
    Ok(())
}

fn client() -> Result<(), std::io::Error> {
    let stream = TcpStream::connect("127.0.0.1:9988").unwrap();
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(100u64)));
    // This client doesn't know any servers, but will use Trust-On-First-Use
    let conn = OssuaryConnection::new(ConnectionType::Client, None).unwrap();
    let _ = event_loop(conn, stream, false);
    Ok(())
}

fn main() {
    let server = thread::spawn(move || { let _ = server(); });
    std::thread::sleep(std::time::Duration::from_millis(500));
    let child = thread::spawn(move || { let _ = client(); });
    let _ = child.join();
    let _ = server.join();
}
