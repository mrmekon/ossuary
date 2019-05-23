// basic_auth.rs
//
// Basic test of Ossuary communication library, with authentication
//
// Establishes a authenticated session between a client and server over a TCP
// connection, and exchanges encrypted messages.  Both client and server only
// accept connections from each other, authenticated with known keys.
//
use ossuary::{OssuaryConnection, ConnectionType};
use ossuary::OssuaryError;

use std::thread;
use std::net::{TcpListener, TcpStream};

fn event_loop<T>(mut conn: OssuaryConnection,
                 mut stream: T,
                 is_server: bool) -> Result<(), std::io::Error>
where T: std::io::Read + std::io::Write {
    // Run the opaque handshake until the connection is established
    loop {
        match conn.handshake_done() {
            Ok(true) => break,
            Ok(false) => {},
            Err(OssuaryError::UntrustedServer(_)) => {
                panic!("Untrusted server, authentication failed!")
            }
            Err(e) => panic!("Handshake failed with error: {:?}", e),
        }
        if conn.send_handshake(&mut stream).is_ok() {
            loop {
                match conn.recv_handshake(&mut stream) {
                    Ok(_) => break,
                    Err(OssuaryError::WouldBlock(_)) => {},
                    _ => panic!("Handshake failed."),
                }
            }
        }
    }

    // Send a message to the other party
    let strings = ("message_from_server", "message_from_client");
    let (mut plaintext, response) = match is_server {
        true => (strings.0.as_bytes(), strings.1.as_bytes()),
        false => (strings.1.as_bytes(), strings.0.as_bytes()),
    };
    let _ = conn.send_data(&mut plaintext, &mut stream);

    // Read a message from the other party
    let mut recv_plaintext = vec!();
    loop {
        match conn.recv_data(&mut stream, &mut recv_plaintext) {
            Ok(_) => {
                println!("(basic_auth) received: {:?}",
                         String::from_utf8(recv_plaintext.clone()).unwrap());
                assert_eq!(recv_plaintext.as_slice(), response);
                break;
            },
            _ => {},
        }
    }
    Ok(())
}

fn server() -> Result<(), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:9988").unwrap();
    let stream: TcpStream = listener.incoming().next().unwrap().unwrap();
    let auth_secret_key = &[
        0x50, 0x29, 0x04, 0x97, 0x62, 0xbd, 0xa6, 0x07,
        0x71, 0xca, 0x29, 0x14, 0xe3, 0x83, 0x19, 0x0e,
        0xa0, 0x9e, 0xd4, 0xb7, 0x1a, 0xf9, 0xc9, 0x59,
        0x3e, 0xa3, 0x1c, 0x85, 0x0f, 0xc4, 0xfa, 0xa2,
    ];
    let client_keys: Vec<&[u8]> = vec![
        &[0xbe, 0x1c, 0xa0, 0x74, 0xf4, 0xa5, 0x8b, 0xbb,
          0xd2, 0x62, 0xa7, 0xf9, 0x52, 0x3b, 0x6f, 0xb0,
          0xbb, 0x9e, 0x86, 0x62, 0x28, 0x7c, 0x33, 0x89,
          0xa2, 0xe1, 0x63, 0xdc, 0x55, 0xde, 0x28, 0x1f]
    ];
    // This server only accepts connections from a single known client
    let mut conn = OssuaryConnection::new(ConnectionType::AuthenticatedServer, Some(auth_secret_key)).unwrap();
    let _ = conn.add_authorized_keys(client_keys).unwrap();
    let _ = event_loop(conn, stream, true);
    Ok(())
}

fn client() -> Result<(), std::io::Error> {
    let stream = TcpStream::connect("127.0.0.1:9988").unwrap();
    let sec_key = &[0x10, 0x86, 0x6e, 0xc4, 0x8a, 0x11, 0xf3, 0xc5,
                    0x6d, 0x77, 0xa6, 0x4b, 0x2f, 0x54, 0xaa, 0x06,
                    0x6c, 0x0c, 0xb4, 0x75, 0xd8, 0xc8, 0x7d, 0x35,
                    0xb4, 0x91, 0xee, 0xd6, 0xac, 0x0b, 0xde, 0xbc];
    let server_public_key = &[
        0x20, 0x88, 0x55, 0x8e, 0xbd, 0x9b, 0x46, 0x1d,
        0xd0, 0x9d, 0xf0, 0x00, 0xda, 0xf4, 0x0f, 0x87,
        0xf7, 0x38, 0x40, 0xc5, 0x54, 0x18, 0x57, 0x60,
        0x74, 0x39, 0x3b, 0xb9, 0x70, 0xe1, 0x46, 0x98,
    ];
    let keys: Vec<&[u8]> = vec![server_public_key];
    // This client only accepts connections to a single known server
    let mut conn = OssuaryConnection::new(ConnectionType::Client, Some(sec_key)).unwrap();
    let _ = conn.add_authorized_keys(keys).unwrap();
    let _ = event_loop(conn, stream, false);
    Ok(())
}

#[test]
fn basic_auth() {
    let server = thread::spawn(move || { let _ = server(); });
    std::thread::sleep(std::time::Duration::from_millis(500));
    let child = thread::spawn(move || { let _ = client(); });
    let _ = child.join();
    let _ = server.join();
}
