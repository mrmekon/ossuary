use crate::{crypto_send_data, crypto_recv_data,
            crypto_send_handshake, crypto_recv_handshake, crypto_handshake_done,
            ConnectionContext, ConnectionType};

#[no_mangle]
pub extern "C" fn ossuary_create_connection(conn_type: u8) -> *mut ConnectionContext {
    let conn_type: ConnectionType = match conn_type {
        0 => ConnectionType::Client,
        1 => ConnectionType::AuthenticatedServer,
        2 => ConnectionType::UnauthenticatedServer,
        _ => { return ::std::ptr::null_mut(); }
    };
    let mut conn = Box::new(ConnectionContext::new(conn_type)); // todo
    let ptr: *mut _ = &mut *conn;
    ::std::mem::forget(conn);
    ptr
}

#[no_mangle]
pub extern "C" fn ossuary_destroy_connection(conn: &mut *mut ConnectionContext) {
    if conn.is_null() {
        return;
    }
    let obj: Box<ConnectionContext> = unsafe { ::std::mem::transmute(*conn) };
    ::std::mem::drop(obj);
    *conn = ::std::ptr::null_mut();
}

#[no_mangle]
pub extern "C" fn ossuary_set_authorized_keys(conn: *mut ConnectionContext, keys: *const *const u8, key_count: u8) -> i32 {
    if conn.is_null() || keys.is_null() {
        return -1 as i32;
    }
    let conn = unsafe { &mut *conn };
    let keys: &[*const u8] = unsafe { std::slice::from_raw_parts(keys, key_count as usize) };
    let mut r_keys: Vec<&[u8]> = Vec::with_capacity(key_count as usize);
    for key in keys {
        if !key.is_null() {
            let key: &[u8] = unsafe { std::slice::from_raw_parts(*key, 32) };
            r_keys.push(key);
        }
    }
    let written = match conn.set_authorized_keys(r_keys) {
        Ok(c) => c as i32,
        Err(_) => -1i32,
    };
    ::std::mem::forget(conn);
    written
}

#[no_mangle]
pub extern "C" fn ossuary_set_secret_key(conn: *mut ConnectionContext, key: *const u8) -> i32 {
    if conn.is_null() || key.is_null() {
        return -1 as i32;
    }
    let conn = unsafe { &mut *conn };
    let key: &[u8] = unsafe { std::slice::from_raw_parts(key, 32) };
    let success = match conn.set_secret_key(key) {
        Ok(_) => 0i32,
        Err(_) => -1i32,
    };
    ::std::mem::forget(conn);
    success
}

#[no_mangle]
pub extern "C" fn ossuary_recv_handshake(conn: *mut ConnectionContext,
                                         in_buf: *const u8, in_buf_len: *mut u16) -> i32 {
    if conn.is_null() || in_buf.is_null() || in_buf_len.is_null() {
        return -1i32;
    }
    let mut conn = unsafe { &mut *conn };
    let inlen = unsafe { *in_buf_len as usize };
    let r_in_buf: &[u8] = unsafe { std::slice::from_raw_parts(in_buf, inlen) };
    let mut slice = r_in_buf;
    let written = match crypto_recv_handshake(&mut conn, &mut slice) {
        Ok(read) => {
            read as u16
        },
        _ => {
            0u16
        }
    };
    ::std::mem::forget(conn);
    written as i32 // TODO
}

#[no_mangle]
pub extern "C" fn ossuary_send_handshake(conn: *mut ConnectionContext,
                                         out_buf: *mut u8, out_buf_len: *mut u16) -> i32 {
    if conn.is_null() || out_buf.is_null() || out_buf_len.is_null() {
        return -1i32;
    }
    let mut conn = unsafe { &mut *conn };
    let outlen = unsafe { *out_buf_len as usize };
    let r_out_buf: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(out_buf, outlen) };
    let mut slice = r_out_buf;
    let more = crypto_send_handshake(&mut conn, &mut slice);
    ::std::mem::forget(conn);
    // TODO: error if data to send is larger than the given buffer
    unsafe { *out_buf_len = (outlen - slice.len()) as u16 };
    more as i32
}

#[no_mangle]
pub extern "C" fn ossuary_handshake_done(conn: *const ConnectionContext) -> i32 {
    if conn.is_null() {
        return -1i32;
    }
    let conn = unsafe { &*conn };
    let done = crypto_handshake_done(&conn);
    ::std::mem::forget(conn);
    match done {
        Ok(done) => done as i32,
        Err(_) => -1i32,
    }
}

#[no_mangle]
pub extern "C" fn ossuary_send_data(conn: *mut ConnectionContext,
                                    in_buf: *mut u8, in_buf_len: u16,
                                    out_buf: *mut u8, out_buf_len: u16) -> i32 {
    if conn.is_null() || in_buf.is_null() || out_buf.is_null() {
        return -1i32;
    }
    let mut conn = unsafe { &mut *conn };
    let r_out_buf: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(out_buf, out_buf_len as usize) };
    let r_in_buf: &[u8] = unsafe { std::slice::from_raw_parts(in_buf, in_buf_len as usize) };
    let mut out_slice = r_out_buf;
    let in_slice = r_in_buf;
    let bytes_written: i32;
    match crypto_send_data(&mut conn, &in_slice, &mut out_slice) {
        Ok(x) => {
            bytes_written = x as i32;
        }
        Err(_) => { return -1; },
    }
    ::std::mem::forget(conn);
    bytes_written
}

#[no_mangle]
pub extern "C" fn ossuary_recv_data(conn: *mut ConnectionContext,
                                    in_buf: *mut u8, in_buf_len: u16,
                                    out_buf: *mut u8, out_buf_len: *mut u16) -> i32 {
    if conn.is_null() || in_buf.is_null() || out_buf.is_null() || out_buf_len.is_null() {
        return -1i32;
    }
    let mut conn = unsafe { &mut *conn };
    let r_out_buf: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(out_buf, *out_buf_len as usize) };
    let r_in_buf: &[u8] = unsafe { std::slice::from_raw_parts(in_buf, in_buf_len as usize) };
    let mut out_slice = r_out_buf;
    let mut in_slice = r_in_buf;
    let bytes_read: u16;
    match crypto_recv_data(&mut conn, &mut in_slice, &mut out_slice) {
        Ok((read,written)) => {
            unsafe { *out_buf_len = written as u16 };
            bytes_read = read as u16;
        },
        Err(_) => {
            return -1;
        },
    }
    ::std::mem::forget(conn);
    bytes_read as i32
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::io::{Write};
    use std::net::{TcpListener, TcpStream};
    use std::io::BufRead;
    use crate::clib::*;

    fn server() -> Result<(), std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:9989").unwrap();
        for stream in listener.incoming() {
            let mut stream: TcpStream = stream.unwrap();
            let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut conn = ossuary_create_connection(1);
            let key: &[u8; 32] = &[0xbe, 0x1c, 0xa0, 0x74, 0xf4, 0xa5, 0x8b, 0xbb,
                                   0xd2, 0x62, 0xa7, 0xf9, 0x52, 0x3b, 0x6f, 0xb0,
                                   0xbb, 0x9e, 0x86, 0x62, 0x28, 0x7c, 0x33, 0x89,
                                   0xa2, 0xe1, 0x63, 0xdc, 0x55, 0xde, 0x28, 0x1f];
            let keys: &[*const u8; 1] = &[key as *const u8];
            ossuary_set_authorized_keys(conn, keys as *const *const u8, keys.len() as u8);

            let out_buf: [u8; 512] = [0; 512];

            while ossuary_handshake_done(conn) == 0 {
                let mut out_len = out_buf.len() as u16;
                let more = ossuary_send_handshake(conn, (&out_buf) as *const u8 as *mut u8, &mut out_len);
                let _ = stream.write_all(&out_buf[0..out_len as usize]).unwrap();

                if more != 0 {
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
            let sz = ossuary_send_data(
                conn,
                (&plaintext) as *const u8 as *mut u8, 13 as u16,
                (&out_buf) as *const u8 as *mut u8, out_buf.len() as u16);
            let _ = stream.write_all(&out_buf[0..sz as usize]).unwrap();

            plaintext[0..13].copy_from_slice("from server 2".as_bytes());
            let sz = ossuary_send_data(
                conn,
                (&plaintext) as *const u8 as *mut u8, 13 as u16,
                (&out_buf) as *const u8 as *mut u8, out_buf.len() as u16);
            let _ = stream.write_all(&out_buf[0..sz as usize]).unwrap();

            let in_buf = reader.fill_buf().unwrap();
            if in_buf.len() > 0 {
                let mut out_len = out_buf.len() as u16;
                let len = ossuary_recv_data(
                    conn,
                    (in_buf) as *const [u8] as *mut u8, in_buf.len() as u16,
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
        let mut conn = ossuary_create_connection(0);
        let key: &[u8; 32] = &[0x10, 0x86, 0x6e, 0xc4, 0x8a, 0x11, 0xf3, 0xc5,
                               0x6d, 0x77, 0xa6, 0x4b, 0x2f, 0x54, 0xaa, 0x06,
                               0x6c, 0x0c, 0xb4, 0x75, 0xd8, 0xc8, 0x7d, 0x35,
                               0xb4, 0x91, 0xee, 0xd6, 0xac, 0x0b, 0xde, 0xbc];
        ossuary_set_secret_key(conn, key as *const u8);

        let out_buf: [u8; 512] = [0; 512];

        let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
        while ossuary_handshake_done(conn) == 0 {
            let mut out_len = out_buf.len() as u16;
            let more = ossuary_send_handshake(conn, (&out_buf) as *const u8 as *mut u8, &mut out_len);
            let _ = stream.write_all(&out_buf[0.. out_len as usize]).unwrap();

            if more != 0 {
                let in_buf = reader.fill_buf().unwrap();
                let mut in_len = in_buf.len() as u16;
                let len = ossuary_recv_handshake(conn, in_buf as *const [u8] as *const u8, &mut in_len);
                reader.consume(len as usize);
            }
        }

        let out_buf: [u8; 256] = [0; 256];
        let mut plaintext: [u8; 256] = [0; 256];
        plaintext[0..11].copy_from_slice("from client".as_bytes());
        let sz = ossuary_send_data(
            conn,
            (&plaintext) as *const u8 as *mut u8, 11 as u16,
            (&out_buf) as *const u8 as *mut u8, out_buf.len() as u16);
        let _ = stream.write_all(&out_buf[0..sz as usize]).unwrap();

        let mut stream = std::io::BufReader::new(stream);
        let mut count = 0;
        loop {
            let in_buf = stream.fill_buf().unwrap();
            if in_buf.len() == 0 || count == 2 {
                break;
            }
            let mut out_len = out_buf.len() as u16;
            let len = ossuary_recv_data(
                conn,
                in_buf as *const [u8] as *mut u8, in_buf.len() as u16,
                (&out_buf) as *const u8 as *mut u8, &mut out_len);
            if len == -1 {
                break;
            }
            if len > 0 {
                println!("CLIB READ: {:?}",
                         std::str::from_utf8(&out_buf[0..out_len as usize]).unwrap());
                stream.consume(len as usize);
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
}
