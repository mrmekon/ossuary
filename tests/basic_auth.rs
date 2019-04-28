use ossuary::{OssuaryConnection, ConnectionType};
use ossuary::OssuaryError;

use std::thread;
use std::net::{TcpListener, TcpStream};

fn event_loop<T>(mut conn: OssuaryConnection,
                 mut stream: T,
                 is_server: bool) -> Result<(), std::io::Error>
where T: std::io::Read + std::io::Write {
    // Run the opaque handshake until the connection is established
    while conn.handshake_done().unwrap() == false {
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
    let mut conn = OssuaryConnection::new(ConnectionType::AuthenticatedServer);
    let keys: Vec<&[u8]> = vec![
        &[0xbe, 0x1c, 0xa0, 0x74, 0xf4, 0xa5, 0x8b, 0xbb,
          0xd2, 0x62, 0xa7, 0xf9, 0x52, 0x3b, 0x6f, 0xb0,
          0xbb, 0x9e, 0x86, 0x62, 0x28, 0x7c, 0x33, 0x89,
          0xa2, 0xe1, 0x63, 0xdc, 0x55, 0xde, 0x28, 0x1f]
    ];
    let _ = conn.set_authorized_keys(keys).unwrap();
    let _ = event_loop(conn, stream, true);
    Ok(())
}

fn client() -> Result<(), std::io::Error> {
    let stream = TcpStream::connect("127.0.0.1:9988").unwrap();
    let mut conn = OssuaryConnection::new(ConnectionType::Client);
    let _ = conn.set_secret_key(
        &[0x10, 0x86, 0x6e, 0xc4, 0x8a, 0x11, 0xf3, 0xc5,
          0x6d, 0x77, 0xa6, 0x4b, 0x2f, 0x54, 0xaa, 0x06,
          0x6c, 0x0c, 0xb4, 0x75, 0xd8, 0xc8, 0x7d, 0x35,
          0xb4, 0x91, 0xee, 0xd6, 0xac, 0x0b, 0xde, 0xbc]).unwrap();
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
