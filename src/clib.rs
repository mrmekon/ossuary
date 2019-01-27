use crate::{ConnectionContext, ConnectionType, OssuaryError};

const ERROR_WOULD_BLOCK: i32 = -64;

#[no_mangle]
pub extern "C" fn ossuary_create_connection(conn_type: u8) -> *mut ConnectionContext {
    let conn_type: ConnectionType = match conn_type {
        0 => ConnectionType::Client,
        1 => ConnectionType::AuthenticatedServer,
        2 => ConnectionType::UnauthenticatedServer,
        _ => { return ::std::ptr::null_mut(); }
    };
    let mut conn = Box::new(ConnectionContext::new(conn_type));
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
pub extern "C" fn ossuary_set_authorized_keys(conn: *mut ConnectionContext,
                                              keys: *const *const u8,
                                              key_count: u8) -> i32 {
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
pub extern "C" fn ossuary_set_secret_key(conn: *mut ConnectionContext,
                                         key: *const u8) -> i32 {
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
    let conn = unsafe { &mut *conn };
    let inlen = unsafe { *in_buf_len as usize };
    let r_in_buf: &[u8] = unsafe { std::slice::from_raw_parts(in_buf, inlen) };
    let mut slice = r_in_buf;
    let read: i32 = match conn.crypto_recv_handshake(&mut slice) {
        Ok(read) => {
            unsafe { *in_buf_len = read as u16; }
            read as i32
        },
        Err(OssuaryError::WouldBlock(b)) => {
            unsafe { *in_buf_len = b as u16; }
            ERROR_WOULD_BLOCK
        },
        _ => -1i32,
    };
    ::std::mem::forget(conn);
    read as i32
}

#[no_mangle]
pub extern "C" fn ossuary_send_handshake(conn: *mut ConnectionContext,
                                         out_buf: *mut u8, out_buf_len: *mut u16) -> i32 {
    if conn.is_null() || out_buf.is_null() || out_buf_len.is_null() {
        return -1i32;
    }
    let conn = unsafe { &mut *conn };
    let outlen = unsafe { *out_buf_len as usize };
    let r_out_buf: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(out_buf, outlen) };
    let mut slice = r_out_buf;
    let wrote: i32 = match conn.crypto_send_handshake(&mut slice) {
        Ok(w) => {
            unsafe { *out_buf_len = w as u16 };
            w as i32
        },
        Err(OssuaryError::WouldBlock(w)) => {
            unsafe { *out_buf_len = w as u16 };
            ERROR_WOULD_BLOCK
        },
        Err(_) => -1,
    };
    ::std::mem::forget(conn);
    wrote
}

#[no_mangle]
pub extern "C" fn ossuary_handshake_done(conn: *const ConnectionContext) -> i32 {
    if conn.is_null() {
        return -1i32;
    }
    let conn = unsafe { &*conn };
    let done = conn.crypto_handshake_done();
    ::std::mem::forget(conn);
    match done {
        Ok(done) => done as i32,
        Err(_) => -1i32,
    }
}

#[no_mangle]
pub extern "C" fn ossuary_send_data(conn: *mut ConnectionContext,
                                    in_buf: *mut u8, in_buf_len: u16,
                                    out_buf: *mut u8, out_buf_len: *mut u16) -> i32 {
    if conn.is_null() || in_buf.is_null() ||
        out_buf.is_null() || out_buf_len.is_null() {
        return -1i32;
    }
    let conn = unsafe { &mut *conn };
    let r_out_buf: &mut [u8] = unsafe {
        std::slice::from_raw_parts_mut(out_buf, *out_buf_len as usize)
    };
    let r_in_buf: &[u8] = unsafe { std::slice::from_raw_parts(in_buf, in_buf_len as usize) };
    let mut out_slice = r_out_buf;
    let in_slice = r_in_buf;
    let bytes_written = match conn.crypto_send_data(&in_slice, &mut out_slice) {
        Ok(w) => {
            unsafe { *out_buf_len = w as u16; }
            w as i32
        },
        Err(OssuaryError::WouldBlock(w)) => {
            unsafe { *out_buf_len = w as u16; }
            ERROR_WOULD_BLOCK
        },
        Err(_) => -1i32,
    };
    ::std::mem::forget(conn);
    bytes_written
}

#[no_mangle]
pub extern "C" fn ossuary_recv_data(conn: *mut ConnectionContext,
                                    in_buf: *mut u8, in_buf_len: *mut u16,
                                    out_buf: *mut u8, out_buf_len: *mut u16) -> i32 {
    if conn.is_null() || in_buf.is_null() || out_buf.is_null() ||
        in_buf_len.is_null() || out_buf_len.is_null() {
        return -1i32;
    }
    let conn = unsafe { &mut *conn };
    let r_out_buf: &mut [u8] = unsafe {
        std::slice::from_raw_parts_mut(out_buf, *out_buf_len as usize)
    };
    let r_in_buf: &[u8] = unsafe { std::slice::from_raw_parts(in_buf, *in_buf_len as usize) };
    let mut out_slice = r_out_buf;
    let mut in_slice = r_in_buf;
    let bytes_read = match conn.crypto_recv_data(&mut in_slice, &mut out_slice) {
        Ok((read,written)) => {
            unsafe {
                *in_buf_len = read as u16;
                *out_buf_len = written as u16;
            };
            read as i32
        },
        Err(OssuaryError::WouldBlock(w)) => {
            unsafe {
                *out_buf_len = w as u16;
            };
            ERROR_WOULD_BLOCK
        },
        Err(_) => -1i32,
    };
    ::std::mem::forget(conn);
    bytes_read as i32
}

#[no_mangle]
pub extern "C" fn ossuary_flush(conn: *mut ConnectionContext,
                                out_buf: *mut u8, out_buf_len: u16) -> i32 {
    if conn.is_null() || out_buf.is_null() {
        return -1i32;
    }
    let conn = unsafe { &mut *conn };
    let r_out_buf: &mut [u8] = unsafe {
        std::slice::from_raw_parts_mut(out_buf, out_buf_len as usize)
    };
    let mut out_slice = r_out_buf;
    let bytes_written = match conn.crypto_flush(&mut out_slice) {
        Ok(x) => x as i32,
        Err(OssuaryError::WouldBlock(_)) => ERROR_WOULD_BLOCK,
        Err(_) => -1i32,
    };
    ::std::mem::forget(conn);
    bytes_written
}
