use ossuary::{ConnectionContext, ConnectionType};
use ossuary::{crypto_send_handshake,crypto_recv_handshake, crypto_handshake_done};
use ossuary::{crypto_send_data,crypto_recv_data};

use std::thread;
use std::net::{TcpListener, TcpStream};

fn event_loop<T>(mut conn: ConnectionContext,
                 mut stream: T,
                 is_server: bool) -> Result<(), std::io::Error>
where T: std::io::Read + std::io::Write {
    // Run the opaque handshake until the connection is established
    while crypto_handshake_done(&conn).unwrap() == false {
        if crypto_send_handshake(&mut conn, &mut stream) {
            crypto_recv_handshake(&mut conn, &mut stream);
        }
    }

    // Send a message to the other party
    let mut plaintext = match is_server {
        true => "message from server".as_bytes(),
        false => "message from client".as_bytes(),
    };
    let _ = crypto_send_data(&mut conn, &mut plaintext, &mut stream);

    // Read a message from the other party
    let mut plaintext = vec!();
    let _ = crypto_recv_data(&mut conn, &mut stream, &mut plaintext);
    println!("(basic) received: {:?}", String::from_utf8(plaintext).unwrap());

    Ok(())
}

fn server() -> Result<(), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:9988").unwrap();
    let stream: TcpStream = listener.incoming().next().unwrap().unwrap();
    let conn = ConnectionContext::new(ConnectionType::UnauthenticatedServer);
    let _ = event_loop(conn, stream, true);
    Ok(())
}

fn client() -> Result<(), std::io::Error> {
    let stream = TcpStream::connect("127.0.0.1:9988").unwrap();
    let conn = ConnectionContext::new(ConnectionType::Client);
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
