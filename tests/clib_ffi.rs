use ossuary::clib::{
    ossuary_create_connection,
    ossuary_destroy_connection,
    ossuary_set_secret_key,
    ossuary_add_authorized_keys,
    ossuary_send_handshake,
    ossuary_recv_handshake,
    ossuary_handshake_done,
    ossuary_send_data,
    ossuary_recv_data,
    ossuary_remote_public_key,
    ossuary_add_authorized_key,
    OSSUARY_ERR_UNTRUSTED_SERVER,
};

use std::thread;
use std::net::{TcpListener, TcpStream};

use std::io::{Write};
use std::io::BufRead;

fn server() -> Result<(), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:9989").unwrap();
    for stream in listener.incoming() {
        let mut stream: TcpStream = stream.unwrap();
        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        let mut conn = ossuary_create_connection(1, ::std::ptr::null_mut());
        let key: &[u8; 32] = &[0xbe, 0x1c, 0xa0, 0x74, 0xf4, 0xa5, 0x8b, 0xbb,
                               0xd2, 0x62, 0xa7, 0xf9, 0x52, 0x3b, 0x6f, 0xb0,
                               0xbb, 0x9e, 0x86, 0x62, 0x28, 0x7c, 0x33, 0x89,
                               0xa2, 0xe1, 0x63, 0xdc, 0x55, 0xde, 0x28, 0x1f];
        let keys: &[*const u8; 1] = &[key as *const u8];
        ossuary_add_authorized_keys(conn, keys as *const *const u8, keys.len() as u8);

        let out_buf: [u8; 512] = [0; 512];

        while ossuary_handshake_done(conn) == 0 {
            let mut out_len = out_buf.len() as u16;
            let wrote = ossuary_send_handshake(conn,
                                               (&out_buf) as *const u8 as *mut u8,
                                               &mut out_len);
            if wrote >= 0 {
                let _ = stream.write_all(&out_buf[0..wrote as usize]).unwrap();
                let in_buf = reader.fill_buf().unwrap();
                let mut in_len = in_buf.len() as u16;
                if in_len > 0 {
                    let len = ossuary_recv_handshake(conn, in_buf as *const [u8] as *const u8, &mut in_len);
                    reader.consume(len as usize);
                }
            }
        }

        let mut plaintext: [u8; 256] = [0; 256];
        plaintext[0..13].copy_from_slice("from server 1".as_bytes());
        let mut out_len: u16 = out_buf.len() as u16;
        let sz = ossuary_send_data(
            conn,
            (&plaintext) as *const u8 as *mut u8, 13 as u16,
            (&out_buf) as *const u8 as *mut u8,
            &mut out_len);
        let _ = stream.write_all(&out_buf[0..sz as usize]).unwrap();

        plaintext[0..13].copy_from_slice("from server 2".as_bytes());
        let mut out_len: u16 = out_buf.len() as u16;
        let sz = ossuary_send_data(
            conn,
            (&plaintext) as *const u8 as *mut u8, 13 as u16,
            (&out_buf) as *const u8 as *mut u8,
            &mut out_len);
        let _ = stream.write_all(&out_buf[0..sz as usize]).unwrap();

        let in_buf = reader.fill_buf().unwrap();
        if in_buf.len() > 0 {
            let mut out_len = out_buf.len() as u16;
            let mut in_len = in_buf.len() as u16;
            let len = ossuary_recv_data(
                conn,
                (in_buf) as *const [u8] as *mut u8, &mut in_len,
                (&out_buf) as *const u8 as *mut u8, &mut out_len);
            if len != -1 {
                println!("CLIB READ: {:?}",
                         std::str::from_utf8(&out_buf[0..out_len as usize]).unwrap());
                reader.consume(len as usize);
            }
        }

        ossuary_destroy_connection(&mut conn);
        break;
    }
    Ok(())
}

fn client() -> Result<(), std::io::Error> {
    let mut stream = TcpStream::connect("127.0.0.1:9989").unwrap();
    let mut conn = ossuary_create_connection(0, ::std::ptr::null_mut());
    let key: &[u8; 32] = &[0x10, 0x86, 0x6e, 0xc4, 0x8a, 0x11, 0xf3, 0xc5,
                           0x6d, 0x77, 0xa6, 0x4b, 0x2f, 0x54, 0xaa, 0x06,
                           0x6c, 0x0c, 0xb4, 0x75, 0xd8, 0xc8, 0x7d, 0x35,
                           0xb4, 0x91, 0xee, 0xd6, 0xac, 0x0b, 0xde, 0xbc];
    ossuary_set_secret_key(conn, key as *const u8);

    let out_buf: [u8; 512] = [0; 512];

    let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
    loop {
        match ossuary_handshake_done(conn) {
            0 => {},
            x if x > 0 => break,
            OSSUARY_ERR_UNTRUSTED_SERVER => {
                let key = [0u8; 32];
                ossuary_remote_public_key(conn, &key as *const u8 as *mut u8, key.len() as u16);
                ossuary_add_authorized_key(conn, &key as *const u8);
                continue;
            },
            x => panic!("handshake failed: {}", x),
        }
        let mut out_len = out_buf.len() as u16;
        let wrote = ossuary_send_handshake(conn,
                                           (&out_buf) as *const u8 as *mut u8,
                                           &mut out_len);
        if wrote >= 0 {
            let _ = stream.write_all(&out_buf[0.. wrote as usize]).unwrap();
            let in_buf = reader.fill_buf().unwrap();
            let mut in_len = in_buf.len() as u16;
            let len = ossuary_recv_handshake(conn,
                                             in_buf as *const [u8] as *const u8,
                                             &mut in_len);
            reader.consume(len as usize);
        }
    }

    let out_buf: [u8; 256] = [0; 256];
    let mut plaintext: [u8; 256] = [0; 256];
    plaintext[0..11].copy_from_slice("from client".as_bytes());
    let mut out_len: u16 = out_buf.len() as u16;
    let sz = ossuary_send_data(
        conn,
        (&plaintext) as *const u8 as *mut u8, 11 as u16,
        (&out_buf) as *const u8 as *mut u8,
        &mut out_len);
    let _ = stream.write_all(&out_buf[0..sz as usize]).unwrap();

    //let mut stream = std::io::BufReader::new(stream);
    let mut count = 0;
    loop {
        let in_buf = reader.fill_buf().unwrap();
        if in_buf.len() == 0 || count == 2 {
            break;
        }
        let mut out_len = out_buf.len() as u16;
        let mut in_len = in_buf.len() as u16;
        let len = ossuary_recv_data(
            conn,
            in_buf as *const [u8] as *mut u8, &mut in_len,
            (&out_buf) as *const u8 as *mut u8, &mut out_len);
        if len == -1 {
            break;
        }
        if len > 0 {
            println!("CLIB READ: {:?}",
                     std::str::from_utf8(&out_buf[0..out_len as usize]).unwrap());
            reader.consume(len as usize);
            count += 1;
        }
    }

    ossuary_destroy_connection(&mut conn);
    Ok(())
}

#[test]
fn test_clib() {
    let server = thread::spawn(move || { let _ = server(); });
    std::thread::sleep(std::time::Duration::from_millis(500));
    let child = thread::spawn(move || { let _ = client(); });
    let _ = child.join();
    let _ = server.join();
}
