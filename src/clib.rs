use crate::{crypto_send_data, crypto_recv_data,
            crypto_send_handshake, crypto_recv_handshake, crypto_handshake_done,
            ConnectionContext};

#[no_mangle]
pub extern "C" fn ossuary_create_connection(is_server: u8) -> *mut ConnectionContext {
    let is_server: bool = match is_server {
        0 => false,
        _ => true,
    };
    let mut conn = Box::new(ConnectionContext::new(is_server)); // todo
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
pub extern "C" fn ossuary_recv_handshake(conn: *mut ConnectionContext,
                                         in_buf: *const u8, in_buf_len: *mut u16) -> i32 {
    if conn.is_null() || in_buf.is_null() || in_buf_len.is_null() {
        return -1i32;
    }
    let mut conn = unsafe { &mut *conn };
    let inlen = unsafe { *in_buf_len as usize };
    let r_in_buf: &[u8] = unsafe { std::slice::from_raw_parts(in_buf, inlen) };
    let mut slice = r_in_buf;
    crypto_recv_handshake(&mut conn, &mut slice);
    ::std::mem::forget(conn);
    unsafe { *in_buf_len = (inlen - slice.len()) as u16 };
    0i32
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
    unsafe { *out_buf_len = (outlen - slice.len()) as u16 };
    more as i32
}

#[no_mangle]
pub extern "C" fn ossuary_handshake_done(conn: *const ConnectionContext) -> u8 {
    if conn.is_null() {
        return 0u8;
    }
    let conn = unsafe { &*conn };
    let done = crypto_handshake_done(&conn);
    ::std::mem::forget(conn);
    done as u8
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
    match crypto_send_data(&mut conn, &in_slice, &mut out_slice) {
        Err(_) => { return -1; },
        _ => {},
    }
    ::std::mem::forget(conn);
    (out_buf_len - out_slice.len() as u16) as i32
}

#[no_mangle]
pub extern "C" fn ossuary_recv_data(conn: *mut ConnectionContext,
                                    in_buf: *mut u8, in_buf_len: u16,
                                    out_buf: *mut u8, out_buf_len: u16) -> i32 {
    if conn.is_null() || in_buf.is_null() || out_buf.is_null() {
        return -1i32;
    }
    let mut conn = unsafe { &mut *conn };
    let r_out_buf: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(out_buf, out_buf_len as usize) };
    let r_in_buf: &[u8] = unsafe { std::slice::from_raw_parts(in_buf, in_buf_len as usize) };
    let mut out_slice = r_out_buf;
    let mut in_slice = r_in_buf;
    match crypto_recv_data(&mut conn, &mut in_slice, &mut out_slice) {
        Ok(_) => {},
        Err(e) => {
            println!("recv_data failed: {} {}", e, conn.is_server);
            return -1; },
    }
    ::std::mem::forget(conn);
    (out_buf_len - out_slice.len() as u16) as i32
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::io::{Read,Write};
    use std::net::{TcpListener, TcpStream};
    use crate::clib::*;
    fn server() -> Result<(), std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:9989").unwrap();
        for stream in listener.incoming() {
            let mut stream: TcpStream = stream.unwrap();
            let mut conn = ossuary_create_connection(1);

            let out_buf: [u8; 256] = [0; 256];
            let mut in_buf: [u8; 256] = [0; 256];

            while ossuary_handshake_done(conn) == 0 {
                let mut out_len = out_buf.len() as u16;
                let more = ossuary_send_handshake(conn, (&out_buf) as *const u8 as *mut u8, &mut out_len);
                let _ = stream.write(&out_buf[0..out_len as usize]);

                if more != 0 {
                    let _ = stream.read(&mut in_buf);
                    let mut in_len = in_buf.len() as u16;
                    ossuary_recv_handshake(conn, (&in_buf) as *const u8, &mut in_len);
                }
            }

            let out_buf: [u8; 256] = [0; 256];
            let mut plaintext: [u8; 256] = [0; 256];
            plaintext[0..13].copy_from_slice("from server 1".as_bytes());
            ossuary_send_data(
                conn,
                (&plaintext) as *const u8 as *mut u8, 13 as u16,
                (&out_buf) as *const u8 as *mut u8, out_buf.len() as u16);
            let _ = stream.write(&out_buf);

            let out_buf: [u8; 256] = [0; 256];
            let mut plaintext: [u8; 256] = [0; 256];
            plaintext[0..13].copy_from_slice("from server 2".as_bytes());
            ossuary_send_data(
                conn,
                (&plaintext) as *const u8 as *mut u8, 13 as u16,
                (&out_buf) as *const u8 as *mut u8, out_buf.len() as u16);
            let _ = stream.write(&out_buf);

            let _ = stream.read(&mut in_buf);
            let out_buf: [u8; 256] = [0; 256];
            let len = ossuary_recv_data(
                conn,
                (&in_buf) as *const u8 as *mut u8, in_buf.len() as u16,
                (&out_buf) as *const u8 as *mut u8, out_buf.len() as u16);
            if len != -1 {
                println!("CLIB READ: {:?}",
                         std::str::from_utf8(&out_buf[0..len as usize]).unwrap());
            }

            ossuary_destroy_connection(&mut conn);
            break;
        }
        Ok(())
    }

    fn client() -> Result<(), std::io::Error> {
        let mut stream = TcpStream::connect("127.0.0.1:9989").unwrap();
        let mut conn = ossuary_create_connection(0);

        let out_buf: [u8; 256] = [0; 256];
        let mut in_buf: [u8; 256] = [0; 256];

        while ossuary_handshake_done(conn) == 0 {
            let mut out_len = out_buf.len() as u16;
            let more = ossuary_send_handshake(conn, (&out_buf) as *const u8 as *mut u8, &mut out_len);
            let _ = stream.write(&out_buf[0.. out_len as usize]);

            if more != 0 {
                let _ = stream.read(&mut in_buf);
                let mut in_len = in_buf.len() as u16;
                ossuary_recv_handshake(conn, (&in_buf) as *const u8, &mut in_len);
            }
        }

        let out_buf: [u8; 256] = [0; 256];
        let mut plaintext: [u8; 256] = [0; 256];
        plaintext[0..11].copy_from_slice("from client".as_bytes());
        ossuary_send_data(
            conn,
            (&plaintext) as *const u8 as *mut u8, 11 as u16,
            (&out_buf) as *const u8 as *mut u8, out_buf.len() as u16);
        let _ = stream.write(&out_buf);

        let _ = stream.read(&mut in_buf);
        let out_buf: [u8; 256] = [0; 256];
        let len = ossuary_recv_data(
            conn,
            (&in_buf) as *const u8 as *mut u8, in_buf.len() as u16,
            (&out_buf) as *const u8 as *mut u8, out_buf.len() as u16);
        if len != -1 {
            println!("CLIB READ: {:?}",
                     std::str::from_utf8(&out_buf[0..len as usize]).unwrap());
        }

        let _ = stream.read(&mut in_buf);
        let out_buf: [u8; 256] = [0; 256];
        let len = ossuary_recv_data(
            conn,
            (&in_buf) as *const u8 as *mut u8, in_buf.len() as u16,
            (&out_buf) as *const u8 as *mut u8, out_buf.len() as u16);
        if len != -1 {
            println!("CLIB READ: {:?}",
                     std::str::from_utf8(&out_buf[0..len as usize]).unwrap());
        }

        ossuary_destroy_connection(&mut conn);
        Ok(())
    }
    #[test]
    fn test() {
        thread::spawn(move || { let _ = server(); });
        let child = thread::spawn(move || { let _ = client(); });
        let _ = child.join();
    }
}
