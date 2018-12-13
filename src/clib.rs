use crate::{crypto_send_handshake, crypto_recv_handshake, ConnectionContext};

#[no_mangle]
pub extern "C" fn ossuary_create_connection() -> *mut ConnectionContext {
    let mut conn = Box::new(ConnectionContext::new());
    let ptr: *mut _ = &mut *conn;
    ::std::mem::forget(conn);
    ptr
}

#[no_mangle]
pub extern "C" fn ossuary_recv_handshake(conn: *mut ConnectionContext, in_buf: *const u8, in_buf_len: u16) -> i32 {
    if conn.is_null() || in_buf.is_null() {
        return -1i32;
    }
    let mut conn = unsafe { &mut *conn };
    let r_in_buf: &[u8] = unsafe { std::slice::from_raw_parts(in_buf, in_buf_len as usize) };
    let mut slice = r_in_buf;
    crypto_recv_handshake(&mut conn, &mut slice);

    ::std::mem::forget(conn);
    (in_buf_len - slice.len() as u16) as i32
}

#[no_mangle]
pub extern "C" fn ossuary_send_handshake(conn: *mut ConnectionContext, in_buf: *mut u8, in_buf_len: u16) -> i32 {
    if conn.is_null() || in_buf.is_null() {
        return -1i32;
    }
    let mut conn = unsafe { &mut *conn };
    let r_in_buf: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(in_buf, in_buf_len as usize) };
    let mut slice = r_in_buf;
    crypto_send_handshake(&mut conn, &mut slice);
    ::std::mem::forget(conn);
    (in_buf_len - slice.len() as u16) as i32
}

#[cfg(test)]
mod tests {
    use crate::ConnectionContext;
    use std::thread;
    use std::io::{Read,Write};
    use std::net::{TcpListener, TcpStream};
    use crate::clib::*;
    pub fn server() -> Result<(), std::io::Error> {
        println!("server start");
        let listener = TcpListener::bind("127.0.0.1:9989").unwrap();
        for stream in listener.incoming() {
            let mut stream: TcpStream = stream.unwrap();
            let conn = ossuary_create_connection();
            let mut in_buf: [u8; 256] = [0; 256];
            ossuary_send_handshake(conn, (&in_buf) as *const u8 as *mut u8, in_buf.len() as u16);
            let _ = stream.write(&in_buf);
            let _ = stream.read(&mut in_buf);
            ossuary_recv_handshake(conn, (&in_buf) as *const u8, in_buf.len() as u16);
            break;
        }
        println!("server done");
        Ok(())
    }

    pub fn client() -> Result<(), std::io::Error> {
        println!("client start");
        let mut stream = TcpStream::connect("127.0.0.1:9989").unwrap();
        let conn = ossuary_create_connection();
        let mut in_buf: [u8; 256] = [0; 256];
        ossuary_send_handshake(conn, (&in_buf) as *const u8 as *mut u8, in_buf.len() as u16);
        let _ = stream.write(&in_buf);
        let _ = stream.read(&mut in_buf);
        ossuary_recv_handshake(conn, (&in_buf) as *const u8, in_buf.len() as u16);
        println!("client done");
        Ok(())
    }
    pub fn test() {
        thread::spawn(move || { let _ = server(); });
        let child = thread::spawn(move || { let _ = client(); });
        let _ = child.join();
    }
    #[test]
    fn it_works() {
        test();
    }
}
