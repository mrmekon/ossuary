use ossuary::{OssuaryContext, ConnectionType};
use ossuary::OssuaryError;

use std::thread;
use std::net::{TcpListener, TcpStream};

fn event_loop<T>(mut conn: OssuaryContext,
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
                println!("(basic) received: {:?}",
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
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(100u64)));
    let conn = OssuaryContext::new(ConnectionType::UnauthenticatedServer);
    let _ = event_loop(conn, stream, true);
    Ok(())
}

fn client() -> Result<(), std::io::Error> {
    let stream = TcpStream::connect("127.0.0.1:9988").unwrap();
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(100u64)));
    let conn = OssuaryContext::new(ConnectionType::Client);
    let _ = event_loop(conn, stream, false);
    Ok(())
}

#[test]
fn basic() {
    let server = thread::spawn(move || { let _ = server(); });
    std::thread::sleep(std::time::Duration::from_millis(500));
    let child = thread::spawn(move || { let _ = client(); });
    let _ = child.join();
    let _ = server.join();
}
