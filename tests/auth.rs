use ossuary::{OssuaryConnection, ConnectionType};
use ossuary::OssuaryError;

const SERVER_SECRET: &[u8] = &[
    0x50, 0x29, 0x04, 0x97, 0x62, 0xbd, 0xa6, 0x07,
    0x71, 0xca, 0x29, 0x14, 0xe3, 0x83, 0x19, 0x0e,
    0xa0, 0x9e, 0xd4, 0xb7, 0x1a, 0xf9, 0xc9, 0x59,
    0x3e, 0xa3, 0x1c, 0x85, 0x0f, 0xc4, 0xfa, 0xa2,
];
const SERVER_PUBLIC: &[u8] = &[
    0x20, 0x88, 0x55, 0x8e, 0xbd, 0x9b, 0x46, 0x1d,
    0xd0, 0x9d, 0xf0, 0x00, 0xda, 0xf4, 0x0f, 0x87,
    0xf7, 0x38, 0x40, 0xc5, 0x54, 0x18, 0x57, 0x60,
    0x74, 0x39, 0x3b, 0xb9, 0x70, 0xe1, 0x46, 0x98,
];
const CLIENT_SECRET: &[u8] = &[
    0x10, 0x86, 0x6e, 0xc4, 0x8a, 0x11, 0xf3, 0xc5,
    0x6d, 0x77, 0xa6, 0x4b, 0x2f, 0x54, 0xaa, 0x06,
    0x6c, 0x0c, 0xb4, 0x75, 0xd8, 0xc8, 0x7d, 0x35,
    0xb4, 0x91, 0xee, 0xd6, 0xac, 0x0b, 0xde, 0xbc,
];
const CLIENT_PUBLIC: &[u8] = &[
    0xbe, 0x1c, 0xa0, 0x74, 0xf4, 0xa5, 0x8b, 0xbb,
    0xd2, 0x62, 0xa7, 0xf9, 0x52, 0x3b, 0x6f, 0xb0,
    0xbb, 0x9e, 0x86, 0x62, 0x28, 0x7c, 0x33, 0x89,
    0xa2, 0xe1, 0x63, 0xdc, 0x55, 0xde, 0x28, 0x1f,
];
//const CLIENT_SECRET2: &[u8] = &[
//    0xb4, 0xa6, 0x07, 0x9c, 0xeb, 0x3b, 0xb4, 0x6b,
//    0x0f, 0xe3, 0x21, 0x15, 0xa0, 0xf0, 0x57, 0x7e,
//    0xac, 0x5b, 0x16, 0x7e, 0xf0, 0x68, 0x22, 0x78,
//    0xab, 0xbb, 0xf2, 0x58, 0x1e, 0x1d, 0x9d, 0xb3,
//];
const CLIENT_PUBLIC2: &[u8] = &[
    0xe8, 0x35, 0x9f, 0xd1, 0xc1, 0x99, 0x55, 0x78,
    0x4a, 0x0a, 0xea, 0xc2, 0x4b, 0x58, 0x5e, 0x30,
    0xfc, 0x76, 0x0e, 0x84, 0x28, 0xe8, 0x6c, 0x85,
    0xb8, 0xe1, 0xa0, 0x47, 0x86, 0x6d, 0xd6, 0xf1,
];

#[derive(Debug)]
enum LoopConn {
    LoopClient,
    LoopServer,
}

enum ExpectedError {
    UntrustedServer,
}

fn is_done(conn: &mut OssuaryConnection, expected_error: &Option<ExpectedError>, tofu: bool) -> bool {
    match conn.handshake_done() {
        Ok(true) => true,
        Ok(false) => false,
        Err(OssuaryError::UntrustedServer(key)) => {
            match expected_error {
                Some(ExpectedError::UntrustedServer) => match tofu {
                    true => { let _ = conn.add_authorized_key(&key).unwrap(); false },
                    false => panic!("UNEXPECTED: no trust-on-first-use"),
                },
                _ => panic!("UNEXPECTED: Untrusted server"),
            }
        },
        Err(e) => panic!("{:?}", e)
    }
}

fn connect(mut client_conn: OssuaryConnection, mut server_conn: OssuaryConnection, expected_error: Option<ExpectedError>, tofu: bool) {
    let mut loop_conn = LoopConn::LoopClient;
    let mut client_buf: Vec<u8> = vec!();
    let mut server_buf: Vec<u8> = vec!();

    loop {
        let (mut send_conn, _recv_conn, mut send_buf, recv_buf) = match loop_conn {
            LoopConn::LoopClient => (&mut client_conn, &mut server_conn, &mut client_buf, &mut server_buf),
            _ => (&mut server_conn, &mut client_conn, &mut server_buf, &mut client_buf),
        };
        let send_done = is_done(&mut send_conn, &expected_error, tofu);
        let recv_done = is_done(&mut send_conn, &expected_error, tofu);
        if send_done && recv_done {
            break;
        }
        send_conn.send_handshake(&mut send_buf).unwrap();
        println!("{:?} {:?}", loop_conn, send_buf);
        match send_conn.recv_handshake(&mut recv_buf.as_slice()) {
            Ok(b) => { recv_buf.drain(0..b); },
            Err(OssuaryError::WouldBlock(b)) => { recv_buf.drain(0..b); },
            Err(e) => panic!("UNEXPECTED: recv failed: {:?}", e),
        }
        loop_conn = match loop_conn {
            LoopConn::LoopClient => LoopConn::LoopServer,
            _ => LoopConn::LoopClient,
        };
    }
}

#[test]
fn auth_no_keys_tofu() {
    // Neither requires authentication, client uses Trust-On-First-Use
    let client_conn = OssuaryConnection::new(ConnectionType::Client, None).unwrap();
    let server_conn = OssuaryConnection::new(ConnectionType::UnauthenticatedServer, None).unwrap();
    connect(client_conn, server_conn, Some(ExpectedError::UntrustedServer), true);
}

#[test]
fn auth_client_key_one_good() {
    // Server requires authentication, client is valid, client uses TOFU
    let client_conn = OssuaryConnection::new(ConnectionType::Client, Some(CLIENT_SECRET.clone())).unwrap();
    let mut server_conn = OssuaryConnection::new(ConnectionType::AuthenticatedServer, None).unwrap();
    let _ = server_conn.add_authorized_key(CLIENT_PUBLIC).unwrap();
    connect(client_conn, server_conn, Some(ExpectedError::UntrustedServer), true);
}
#[test]
fn auth_client_key_many_good() {
    // Server requires authentication, client is valid, client uses TOFU
    let client_conn = OssuaryConnection::new(ConnectionType::Client, Some(CLIENT_SECRET.clone())).unwrap();
    let mut server_conn = OssuaryConnection::new(ConnectionType::AuthenticatedServer, None).unwrap();
    let keys = vec!(CLIENT_PUBLIC, CLIENT_PUBLIC2);
    let _ = server_conn.add_authorized_keys(keys).unwrap();
    connect(client_conn, server_conn, Some(ExpectedError::UntrustedServer), true);
}
#[test]
#[should_panic(expected = "InvalidKey")]
fn auth_client_key_one_bad() {
    // Server requires authentication, client is invalid, expected failure
    let client_conn = OssuaryConnection::new(ConnectionType::Client, Some(CLIENT_SECRET.clone())).unwrap();
    let mut server_conn = OssuaryConnection::new(ConnectionType::AuthenticatedServer, None).unwrap();
    let _ = server_conn.add_authorized_key(CLIENT_PUBLIC2).unwrap();
    connect(client_conn, server_conn, Some(ExpectedError::UntrustedServer), true);
}
#[test]
#[should_panic(expected = "InvalidKey")]
fn auth_client_key_many_bad() {
    // Server requires authentication, client is invalid, expected failure
    let client_conn = OssuaryConnection::new(ConnectionType::Client, Some(CLIENT_SECRET.clone())).unwrap();
    let mut server_conn = OssuaryConnection::new(ConnectionType::AuthenticatedServer, None).unwrap();
    let keys = vec!(SERVER_PUBLIC, CLIENT_PUBLIC2);
    let _ = server_conn.add_authorized_keys(keys).unwrap();
    connect(client_conn, server_conn, Some(ExpectedError::UntrustedServer), true);
}
#[test]
fn auth_server_key_good() {
    // Client requires authentication
    let mut client_conn = OssuaryConnection::new(ConnectionType::Client, None).unwrap();
    let server_conn = OssuaryConnection::new(ConnectionType::UnauthenticatedServer, Some(SERVER_SECRET.clone())).unwrap();
    let _ = client_conn.add_authorized_key(SERVER_PUBLIC).unwrap();
    connect(client_conn, server_conn, None, false);
}
#[test]
#[should_panic(expected = "Untrusted server")]
fn auth_server_key_bad() {
    // Client require authentication, expected failure
    let mut client_conn = OssuaryConnection::new(ConnectionType::Client, None).unwrap();
    let server_conn = OssuaryConnection::new(ConnectionType::UnauthenticatedServer, Some(SERVER_SECRET.clone())).unwrap();
    let _ = client_conn.add_authorized_key(CLIENT_PUBLIC2).unwrap();
    connect(client_conn, server_conn, None, false);
}
#[test]
fn auth_client_server_keys_good() {
    // Server and client require authentication
    let mut client_conn = OssuaryConnection::new(ConnectionType::Client, Some(CLIENT_SECRET.clone())).unwrap();
    let mut server_conn = OssuaryConnection::new(ConnectionType::AuthenticatedServer, Some(SERVER_SECRET.clone())).unwrap();
    let _ = server_conn.add_authorized_key(CLIENT_PUBLIC).unwrap();
    let _ = client_conn.add_authorized_key(SERVER_PUBLIC).unwrap();
    connect(client_conn, server_conn, None, false);
}
#[test]
#[should_panic(expected = "Untrusted server")]
fn auth_client_server_keys_bad() {
    // Server and client require authentication, expected failure
    let mut client_conn = OssuaryConnection::new(ConnectionType::Client, Some(CLIENT_SECRET.clone())).unwrap();
    let mut server_conn = OssuaryConnection::new(ConnectionType::AuthenticatedServer, Some(SERVER_SECRET.clone())).unwrap();
    let _ = server_conn.add_authorized_key(CLIENT_PUBLIC2).unwrap();
    let _ = client_conn.add_authorized_key(CLIENT_PUBLIC).unwrap();
    connect(client_conn, server_conn, None, false);
}
