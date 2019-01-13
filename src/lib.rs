#![feature(test)]
#![feature(try_from)]

extern crate x25519_dalek;
extern crate rand;
extern crate chacha20_poly1305_aead;

use chacha20_poly1305_aead::{encrypt,decrypt};
use x25519_dalek::generate_secret;
use x25519_dalek::generate_public;
use x25519_dalek::diffie_hellman;

//use rand::thread_rng;
use rand::RngCore;
use rand::rngs::OsRng;

use std::convert::TryInto;

pub mod clib;

const MAX_PUB_KEY_ACK_TIME: u64 = 3u64;
//
// API:
//  * sock -- TCP data socket
//  * data -- unencrypted data to send
// Goal:
//  Encrypt data, then HMAC data.  Send both.
//  First a handshake is performed:
//    while (!handshake_done):
//      write(sock, crypto_send_handshake())
//      crypto_read_handshake(read(sock))
//  Each data packet to send is given to a crypto_prepare() function
//  Result of crypto_wrap() is put on sock.
//  Response from sock is put in crypto_unwrap()
//  Crypto module internal data:
//   * nonce -- random session counter from server (12 bytes)
//   * local_msg_id -- ID of current message, incremented for each sent message
//   * remote_msg_id -- ID of current message, incremented for each received message
//   * priv_key -- random session private key
//   * pub_key -- pub key matching priv_key
//   * sess_key -- ECDH shared session key
//   * edata -- data encrypted with sess_key, nonce + msg_id
//   * hmac -- hmac of encrypted data
//  Each crypto call returns a data struct with:
//   * as_bytes() -- return something suitable for sticking directly on socket
//   * data() -- return the encrypted data buffer
//   * hmac() -- return the HMAC of the encrypted data
//   * nonce() -- return the session nonce
//   * msg_id() -- msg_id encoded in this data
//  Message:
//   * msg_id: u32 (unencrypted)
//   * data_len: u32 (unencrypted)
//   * hmac_len: u8 (unencrypted) (always 16)
//   * hmac (unencrypted)
//   * data (encrypted)
//

fn struct_as_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::std::slice::from_raw_parts(
            (p as *const T) as *const u8,
            ::std::mem::size_of::<T>(),
        )
    }
}
fn slice_as_struct<T>(p: &[u8]) -> Result<&T, &'static str> {
    unsafe {
        if p.len() < ::std::mem::size_of::<T>() {
            return Err("Cannot cast bytes to struct: size mismatch");
        }
        Ok(&*(&p[..::std::mem::size_of::<T>()] as *const [u8] as *const T))
    }
}

pub enum OssuaryError {
    Io(std::io::Error),
    Unpack(core::array::TryFromSliceError),
}
impl std::fmt::Debug for OssuaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "OssuaryError")
    }
}
impl From<std::io::Error> for OssuaryError {
    fn from(error: std::io::Error) -> Self {
        OssuaryError::Io(error)
    }
}
impl From<core::array::TryFromSliceError> for OssuaryError {
    fn from(error: core::array::TryFromSliceError) -> Self {
        OssuaryError::Unpack(error)
    }
}

#[repr(C,packed)]
struct HandshakePacket {
    len: u16,
    _reserved: u16,
    public_key: [u8; 32],
    nonce: [u8; 12],
}
impl Default for HandshakePacket {
    fn default() -> HandshakePacket {
        HandshakePacket {
        len: 48,
        _reserved: 0u16,
        public_key: [0u8; 32],
        nonce: [0u8; 12],
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy)]
enum PacketType {
    Unknown = 0x00,
    PublicKeyNonce = 0x01,
    PubKeyAck = 0x02,
    AuthRequest = 0x03,
    Reset = 0x04,
    Disconnect = 0x05,
    EncryptedData = 0x10,
}
impl PacketType {
    pub fn from_u16(i: u16) -> PacketType {
        match i {
            0x01 => PacketType::PublicKeyNonce,
            0x02 => PacketType::PubKeyAck,
            0x03 => PacketType::AuthRequest,
            0x04 => PacketType::Reset,
            0x05 => PacketType::Disconnect,
            0x10 => PacketType::EncryptedData,
            _ => PacketType::Unknown,
        }
    }
}

#[repr(C,packed)]
struct EncryptedPacket {
    data_len: u16,
    tag_len: u16,
}

#[repr(C,packed)]
struct PacketHeader {
    len: u16,
    msg_id: u16,
    packet_type: PacketType,
    _reserved: u16,
}

struct NetworkPacket {
    header: PacketHeader,
    data: Box<[u8]>,
}
impl NetworkPacket {
    fn kind(&self) -> PacketType {
        self.header.packet_type
    }
}

enum ConnectionState {
    ServerNew,
    ServerSendPubKey,
    ServerWaitAck(std::time::SystemTime),

    ClientNew,
    ClientWaitKey(std::time::SystemTime),
    ClientSendAck,

    Encrypted,
}
struct KeyMaterial {
    secret: Option<[u8; 32]>,
    public: [u8; 32],
    session: Option<[u8; 32]>,
    nonce: [u8; 12],
}
pub struct ConnectionContext {
    state: ConnectionState,
    is_server: bool,
    local_key: KeyMaterial,
    remote_key: Option<KeyMaterial>,
    local_msg_id: u16,
    remote_msg_id: u16,
}
impl ConnectionContext {
    fn new(server: bool) -> ConnectionContext {
        //let mut rng = thread_rng();
        let mut rng = OsRng::new().unwrap();
        let sec_key = generate_secret(&mut rng);
        let pub_key = generate_public(&sec_key);
        let mut nonce: [u8; 12] = [0; 12];
        rng.fill_bytes(&mut nonce);
        let key = KeyMaterial {
            secret: Some(sec_key),
            public: pub_key.to_bytes(),
            nonce: nonce,
            session: None,
        };
        ConnectionContext {
            state: match server {
                true => ConnectionState::ServerNew,
                false => ConnectionState::ClientNew,
            },
            is_server: server,
            local_key: key,
            remote_key: None,
            local_msg_id: 0u16,
            remote_msg_id: 0u16,
        }
    }
    fn reset_state(&mut self) {
        self.state = match self.is_server {
            true => ConnectionState::ServerNew,
            false => ConnectionState::ClientNew,
        };
    }
    fn add_remote_key(&mut self, public: &[u8; 32], nonce: &[u8; 12]) {
        let key = KeyMaterial {
            secret: None,
            public: public.to_owned(),
            nonce: nonce.to_owned(),
            session: None,
        };
        self.remote_key = Some(key);
        self.local_key.session = Some(diffie_hellman(self.local_key.secret.as_ref().unwrap(), public));
    }
}

fn interpret_packet<'a, T>(pkt: &'a NetworkPacket) -> Result<&'a T, &'static str> {
    let s: &T = slice_as_struct(&pkt.data)?;
    Ok(s)
}

fn interpret_packet_extra<'a, T>(pkt: &'a NetworkPacket) -> Result<(&'a T, &[u8]), &'static str> {
    let s: &T = slice_as_struct(&pkt.data)?;
    Ok((s, &pkt.data[::std::mem::size_of::<T>()..]))
}

fn read_packet<T,U>(mut stream: T) -> Result<NetworkPacket, OssuaryError>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Read {
    let mut buf: Box<[u8]> = Box::new([0u8; ::std::mem::size_of::<PacketHeader>()]);
    let _ = stream.read_exact(&mut buf)?;
    let hdr = PacketHeader {
        len: u16::from_be_bytes(buf[0..2].try_into()?),
        msg_id: u16::from_be_bytes(buf[2..4].try_into()?),
        packet_type: PacketType::from_u16(u16::from_be_bytes(buf[4..6].try_into()?)),
        _reserved: u16::from_be_bytes(buf[6..8].try_into()?),
    };
    let mut buf: Box<[u8]> = vec![0u8; hdr.len as usize].into_boxed_slice();
    let _ = stream.read_exact(&mut buf)?;
    Ok(NetworkPacket {
        header: hdr,
        data: buf,
    })
}

fn write_packet<T,U>(stream: &mut T, data: &[u8], msg_id: &mut u16, kind: PacketType) -> Result<(), std::io::Error>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Write {
    let mut buf: Vec<u8> = Vec::with_capacity(::std::mem::size_of::<PacketHeader>());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(&(*msg_id as u16).to_be_bytes());
    buf.extend_from_slice(&(kind as u16).to_be_bytes());
    buf.extend_from_slice(&(0u16).to_be_bytes());
    let _ = stream.write(&buf)?;
    let _ = stream.write(data)?;
    *msg_id = *msg_id + 1;
    Ok(())
}

pub fn crypto_send_handshake<T,U>(conn: &mut ConnectionContext, mut buf: T) -> bool
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Write {
    let mut next_msg_id = conn.local_msg_id;
    let more = match conn.state {
        ConnectionState::ServerNew => {
            // wait for client
            true
        },
        ConnectionState::ServerWaitAck(t) => {
            // TIMEOUT NACK
            if let Ok(dur) = t.elapsed() {
                if dur.as_secs() > MAX_PUB_KEY_ACK_TIME {
                    let pkt: HandshakePacket = Default::default();
                    let _ = write_packet(&mut buf, struct_as_slice(&pkt),
                                         &mut next_msg_id, PacketType::Reset);
                    conn.state = ConnectionState::ServerNew;
                }
            }
            true
        },
        ConnectionState::ServerSendPubKey => {
            // Send pubkey
            let mut pkt: HandshakePacket = Default::default();
            pkt.public_key.copy_from_slice(&conn.local_key.public);
            pkt.nonce.copy_from_slice(&conn.local_key.nonce);
            let _ = write_packet(&mut buf, struct_as_slice(&pkt),
                                 &mut next_msg_id, PacketType::PublicKeyNonce);
            conn.state = ConnectionState::ServerWaitAck(std::time::SystemTime::now());
            true
        },
        ConnectionState::ClientNew => {
            // Send pubkey
            let mut pkt: HandshakePacket = Default::default();
            pkt.public_key.copy_from_slice(&conn.local_key.public);
            pkt.nonce.copy_from_slice(&conn.local_key.nonce);
            let _ = write_packet(&mut buf, struct_as_slice(&pkt),
                                 &mut next_msg_id, PacketType::PublicKeyNonce);
            conn.state = ConnectionState::ClientWaitKey(std::time::SystemTime::now());
            true
        },
        ConnectionState::ClientWaitKey(t) => {
            if let Ok(dur) = t.elapsed() {
                if dur.as_secs() > MAX_PUB_KEY_ACK_TIME {
                    conn.state = ConnectionState::ClientNew;
                }
            }
            true
        },
        ConnectionState::ClientSendAck => {
            let pkt: HandshakePacket = Default::default();
            let _ = write_packet(&mut buf, struct_as_slice(&pkt),
                                 &mut next_msg_id, PacketType::PubKeyAck);
            conn.state = ConnectionState::Encrypted;
            false
        },
        ConnectionState::Encrypted => {
            false
        },
    };
    conn.local_msg_id = next_msg_id;
    more
}

pub fn crypto_recv_handshake<T,U>(conn: &mut ConnectionContext, buf: T)
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Read {
    // TODO: read_exact won't work.
    let pkt = read_packet(buf);
    if pkt.is_err() {
        return;
    }
    let pkt: NetworkPacket = pkt.unwrap();

    if pkt.header.msg_id != conn.remote_msg_id {
        println!("Message gap detected.  Restarting connection.");
        conn.reset_state();
        return; // TODO: return error
    }
    conn.remote_msg_id = pkt.header.msg_id + 1;

    let mut error = false;
    match pkt.kind() {
        PacketType::Reset => {
            conn.state = match conn.is_server {
                true => ConnectionState::ServerNew,
                _ => ConnectionState::ClientNew,
            };
            return;
        },
        _ => {},
    }

    match conn.state {
        ConnectionState::ServerNew => {
            match pkt.kind() {
                PacketType::PublicKeyNonce => {
                    let data_pkt: &HandshakePacket = interpret_packet(&pkt).as_ref().unwrap();
                    conn.add_remote_key(&data_pkt.public_key, &data_pkt.nonce);
                    conn.state = ConnectionState::ServerSendPubKey;
                },
                _ => { error = true; }
            }
        },
        ConnectionState::ServerWaitAck(_t) => {
            match pkt.kind() {
                PacketType::PubKeyAck => {
                    conn.state = ConnectionState::Encrypted;
                },
                _ => { error = true; }
            }
        },
        ConnectionState::ServerSendPubKey => {
            error = true;
        }, // nop
        ConnectionState::ClientNew => {
            error = true;
        }, // nop
        ConnectionState::ClientWaitKey(_t) => {
            match pkt.kind() {
                PacketType::PublicKeyNonce => {
                    let data_pkt: &HandshakePacket = interpret_packet(&pkt).as_ref().unwrap();
                    conn.add_remote_key(&data_pkt.public_key, &data_pkt.nonce);
                    conn.state = ConnectionState::ClientSendAck;
                },
                _ => { }
            }
        },
        ConnectionState::ClientSendAck => {
            error = true;
        }, // nop
        ConnectionState::Encrypted => {
            error = true;
        }, // nop
    }
    if error {
        conn.state = match conn.is_server {
            true => ConnectionState::ServerNew,
            _ => ConnectionState::ClientNew,
        };
    }
}

pub fn crypto_handshake_done(conn: &ConnectionContext) -> bool {
    match conn.state {
        ConnectionState::Encrypted => true,
        _ => false,
    }
}

pub fn crypto_send_data<T,U>(conn: &mut ConnectionContext, in_buf: &[u8], mut out_buf: T) -> Result<u16, &'static str>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Write {
    match conn.state {
        ConnectionState::Encrypted => {},
        _ => { return Err("Encrypted channel not established."); }
    }
    let mut next_msg_id = conn.local_msg_id;
    let bytes;
    let aad = [];
    let mut ciphertext = Vec::with_capacity(in_buf.len());
    let tag = encrypt(conn.local_key.session.as_ref().unwrap(),
                      &conn.local_key.nonce, &aad, in_buf, &mut ciphertext).unwrap();

    let pkt: EncryptedPacket = EncryptedPacket {
        tag_len: tag.len() as u16,
        data_len: ciphertext.len() as u16,
    };
    let mut buf: Vec<u8>= vec![];
    buf.extend(struct_as_slice(&pkt));
    buf.extend(&ciphertext);
    buf.extend(&tag);
    let _ = write_packet(&mut out_buf, &buf,
                         &mut next_msg_id, PacketType::EncryptedData);
    bytes = buf.len() as u16;
    conn.local_msg_id = next_msg_id;
    Ok(bytes)
}

pub fn crypto_recv_data<T,U,R,V>(conn: &mut ConnectionContext, in_buf: T, mut out_buf: R) -> Result<u16, &'static str>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Read,
      R: std::ops::DerefMut<Target = V>,
      V: std::io::Write {
    let mut bytes: u16 = 0u16;
    match conn.state {
        ConnectionState::Encrypted => {},
        _ => { return Err("Encrypted channel not established."); }
    }
    //if let Ok(pkt) = read_packet(in_buf) {
    match read_packet(in_buf) {
        Ok(pkt) => {
            if pkt.header.msg_id != conn.remote_msg_id {
                println!("Message gap detected.  Restarting connection.");
                conn.reset_state();
                return Ok(0u16); // TODO: return error
            }
            conn.remote_msg_id = pkt.header.msg_id + 1;

            match pkt.kind() {
                PacketType::EncryptedData => {
                    let (data_pkt, rest) = interpret_packet_extra::<EncryptedPacket>(&pkt).unwrap();
                    let ciphertext = &rest[..data_pkt.data_len as usize];
                    let tag = &rest[data_pkt.data_len as usize..];
                    let aad = [];
                    let mut plaintext = Vec::with_capacity(ciphertext.len());
                    let _ = decrypt(conn.local_key.session.as_ref().unwrap(),
                                    &conn.remote_key.as_ref().unwrap().nonce,
                                    &aad, &ciphertext, &tag, &mut plaintext);
                    let _ = out_buf.write(&plaintext);
                    bytes = ciphertext.len() as u16;
                },
                _ => {
                    println!("bad packet: {:x}", pkt.kind() as u16);
                    return Err("Received non-encrypted data on encrypted channel.");
                },
            }
        },
        Err(_e) => {
            // TODO
        },
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    extern crate test;
    use test::Bencher;
    use std::thread;
    use std::net::{TcpListener, TcpStream};
    use crate::*;

    fn event_loop<T>(mut conn: ConnectionContext,
                     mut stream: T,
                     is_server: bool) -> Result<(), std::io::Error>
    where T: std::io::Read + std::io::Write {
        while crypto_handshake_done(&conn) == false {
            if crypto_send_handshake(&mut conn, &mut stream) {
                crypto_recv_handshake(&mut conn, &mut stream);
            }
        }

        if is_server {
            let mut plaintext = "message from server".as_bytes();
            let _ = crypto_send_data(&mut conn, &mut plaintext, &mut stream);
        }
        else {
            let mut plaintext = "message from client".as_bytes();
            let _ = crypto_send_data(&mut conn, &mut plaintext, &mut stream);
        }

        let mut plaintext = vec!();
        let _ = crypto_recv_data(&mut conn, &mut stream, &mut plaintext);
        println!("LIB READ: {:?}", String::from_utf8(plaintext).unwrap());
        Ok(())
    }


    fn server() -> Result<(), std::io::Error> {
        let listener = TcpListener::bind("127.0.0.1:9988").unwrap();
        for stream in listener.incoming() {
            let stream: TcpStream = stream.unwrap();
            let conn = ConnectionContext::new(true);
            let _ = event_loop(conn, stream, true);
        }
        Ok(())
    }

    fn client() -> Result<(), std::io::Error> {
        let stream = TcpStream::connect("127.0.0.1:9988").unwrap();
        let conn = ConnectionContext::new(false);
        let _ = event_loop(conn, stream, false);
        Ok(())
    }

    #[test]
    fn test() {
        thread::spawn(move || { let _ = server(); });
        let child = thread::spawn(move || { let _ = client(); });
        let _ = child.join();
    }

    #[bench]
    fn bench_test(b: &mut Bencher) {
        let server_thread = thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:9987").unwrap();
            let mut server_stream = listener.incoming().next().unwrap().unwrap();
            let mut server_conn = ConnectionContext::new(true);
            while crypto_handshake_done(&server_conn) == false {
                if crypto_send_handshake(&mut server_conn, &mut server_stream) {
                    crypto_recv_handshake(&mut server_conn, &mut server_stream);
                }
            }
            let mut plaintext = vec!();
            let mut bytes: u64 = 0;
            let start = std::time::SystemTime::now();
            loop {
                bytes += crypto_recv_data(&mut server_conn,
                                          &mut server_stream,
                                          &mut plaintext).unwrap() as u64;
                if plaintext == [0xde, 0xde, 0xbe, 0xbe] {
                    if let Ok(dur) = start.elapsed() {
                        let t = dur.as_secs() as f64
                            + dur.subsec_nanos() as f64 * 1e-9;
                        println!("Benchmark done (recv): {} bytes in {:.2} s", bytes, t);
                        println!("{:.2} MB/s", bytes as f64 / 1024.0 / 1024.0 / t);
                    }
                    break;
                }
                plaintext.clear();
            }
        });

        let mut client_stream = TcpStream::connect("127.0.0.1:9987").unwrap();
        let mut client_conn = ConnectionContext::new(false);
        while crypto_handshake_done(&client_conn) == false {
            if crypto_send_handshake(&mut client_conn, &mut client_stream) {
                crypto_recv_handshake(&mut client_conn, &mut client_stream);
            }
        }
        let mut client_stream = std::io::BufWriter::new(client_stream);
        let mut bytes: u64 = 0;
        let start = std::time::SystemTime::now();
        let mut plaintext: &[u8] = &[0xaa; 16384];
        b.iter(|| {
            bytes += crypto_send_data(&mut client_conn,
                                      &mut plaintext,
                                      &mut client_stream).unwrap() as u64;
        });
        if let Ok(dur) = start.elapsed() {
            let t = dur.as_secs() as f64
                + dur.subsec_nanos() as f64 * 1e-9;
            println!("Benchmark done (xmit): {} bytes in {:.2} s", bytes, t);
            println!("{:.2} MB/s", bytes as f64 / 1024.0 / 1024.0 / t);
        }
        let mut plaintext: &[u8] = &[0xde, 0xde, 0xbe, 0xbe];
        let _ = crypto_send_data(&mut client_conn, &mut plaintext, &mut client_stream);
        // Unwrap the BufWriter, flushing the buffer
        let _ = client_stream.into_inner().unwrap();
        let _ = server_thread.join();
    }
}
