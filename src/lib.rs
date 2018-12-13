extern crate x25519_dalek;
extern crate rand;
extern crate chacha20_poly1305_aead;

use chacha20_poly1305_aead::{encrypt,decrypt};
use x25519_dalek::generate_secret;
use x25519_dalek::generate_public;
use x25519_dalek::diffie_hellman;

use rand::thread_rng;
use rand::RngCore;

use std::thread;
use std::rc::Rc;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::net::{TcpListener, TcpStream};

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
#[repr(packed)]
#[allow(dead_code)]
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
#[allow(dead_code)]
enum PacketType {
    PublicKeyNonce,
    AuthRequest,
    EncryptedData,
    Disconnect,
}

#[repr(packed)]
#[allow(dead_code)]
struct EncryptedPacket {
    data_len: u16,
    tag_len: u16,
}

#[repr(packed)]
#[allow(dead_code)]
struct PacketHeader {
    len: u16,
    msg_id: u16,
    packet_type: PacketType,
    _reserved: u16,
}

enum ConnectionState {
    New,
    Encrypted,
    _Authenticated,
}
struct KeyMaterial {
    secret: Option<[u8; 32]>,
    public: [u8; 32],
    session: Option<[u8; 32]>,
    nonce: [u8; 12],
}
struct ConnectionContext {
    stream: Rc<RefCell<TcpStream>>,
    state: ConnectionState,
    local_key: KeyMaterial,
    remote_key: Option<KeyMaterial>,
}
impl ConnectionContext {
    fn new(stream: TcpStream) -> ConnectionContext {
        let mut rng = thread_rng();
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
            stream: Rc::new(RefCell::new(stream)),
            state: ConnectionState::New,
            local_key: key,
            remote_key: None,
        }
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
        self.state = ConnectionState::Encrypted;
    }
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

fn interpret_packet<'a, T>(pkt: &'a NetworkPacket) -> Result<&'a T, &'static str> {
    let s: &T = slice_as_struct(&pkt.data)?;
    Ok(s)
}

fn interpret_packet_extra<'a, T>(pkt: &'a NetworkPacket) -> Result<(&'a T, &[u8]), &'static str> {
    let s: &T = slice_as_struct(&pkt.data)?;
    Ok((s, &pkt.data[::std::mem::size_of::<T>()..]))
}

//fn read_packet<T>(stream: &mut T) -> Result<NetworkPacket, std::io::Error>
//where T: std::io::Read {
fn read_packet<T,U>(mut stream: T) -> Result<NetworkPacket, std::io::Error>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Read {
    let mut buf: Box<[u8]> = Box::new([0u8; ::std::mem::size_of::<PacketHeader>()]);
    println!("read header");
    let _ = stream.read_exact(&mut buf)?;
    let hdr = PacketHeader {
        len: unsafe {
            u16::from_be(std::slice::from_raw_parts(buf.as_ptr() as *const u16, buf.len())[0])
        },
        msg_id: unsafe {
            u16::from_be(std::slice::from_raw_parts(buf.as_ptr() as *const u16, buf.len())[1])
        },
        packet_type: unsafe {
            std::mem::transmute(u16::from_be(std::slice::from_raw_parts(buf.as_ptr() as *const u16, buf.len())[2]))
        },
        _reserved: unsafe {
            u16::from_be(std::slice::from_raw_parts(buf.as_ptr() as *const u16, buf.len())[3])
        },
    };
    let mut buf: Box<[u8]> = vec![0u8; hdr.len as usize].into_boxed_slice();
    let _ = stream.read_exact(&mut buf)?;
    Ok(NetworkPacket {
        header: hdr,
        data: buf,
    })
}

//fn write_packet<T>(stream: &mut T, data: &[u8], msg_id: u16, kind: PacketType) -> Result<(), std::io::Error>
//where T: std::io::Write {
fn write_packet<T,U>(mut stream: T, data: &[u8], msg_id: u16, kind: PacketType) -> Result<(), std::io::Error>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Write {
    let buf: Box<[u8]> = Box::new([0u8; ::std::mem::size_of::<PacketHeader>()]);
    unsafe {
        std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u16, buf.len())[0] = u16::to_be(data.len() as u16);
    }
    unsafe {
        std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u16, buf.len())[1] = u16::to_be(msg_id);
    }
    unsafe {
        std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u16, buf.len())[2] = u16::to_be(kind as u16);
    }
    unsafe {
        std::slice::from_raw_parts_mut(buf.as_ptr() as *mut u16, buf.len())[3] = u16::to_be(0u16);
    }
    stream.write(&buf)?;
    stream.write(data)?;
    Ok(())
}

//fn crypto_send_handshake<T>(conn: &ConnectionContext, buf: &mut T)
//where T: std::io::Write {
fn crypto_send_handshake<T,U>(conn: &ConnectionContext, buf: T)
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Write {
    match conn.state {
        ConnectionState::New => {
            let mut pkt: HandshakePacket = Default::default();
            pkt.public_key.copy_from_slice(&conn.local_key.public);
            pkt.nonce.copy_from_slice(&conn.local_key.nonce);
            let _ = write_packet(buf, struct_as_slice(&pkt), 0, PacketType::PublicKeyNonce);
        },
        _ => {}
    }
}

fn crypto_recv_handshake<T,U>(conn: &mut ConnectionContext, buf: T) -> bool
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Read {
    match conn.state {
        ConnectionState::New => {},
        _ => { return false; }
    }
    // TODO: read_exact won't work.
    if let Ok(pkt) = read_packet(buf) {
        println!("Packet type: {}", pkt.kind() as u16);
        match pkt.kind() {
            _ => {},
        }
    }
    true
}

//fn crypto_send_data(conn: &ConnectionContext, buf: &[u8]) {
//}
//fn crypto_recv_data(conn: &ConnectionContext, buf: &mut [u8]) {
//}

//pub fn event_loop(stream: &mut TcpStream, is_server: bool) -> Result<(), std::io::Error> {
fn event_loop(mut conn: ConnectionContext, is_server: bool) -> Result<(), std::io::Error> {
    println!("conn: {} {}", conn.stream.borrow().peer_addr().unwrap(), is_server);

    crypto_send_handshake(&conn, conn.stream.borrow_mut());
    //let mut pkt: HandshakePacket = Default::default();
    //pkt.public_key.copy_from_slice(&conn.local_key.public);
    //pkt.nonce.copy_from_slice(&conn.local_key.nonce);
    //let _ = write_packet(&mut conn.stream, struct_as_slice(&pkt), 0, PacketType::PublicKeyNonce);

    let mut pkt_queue: VecDeque<NetworkPacket> = VecDeque::with_capacity(20);
    loop {
        pkt_queue.push_back(read_packet(conn.stream.borrow_mut())?);
        if let Some(pkt) = pkt_queue.pop_front() {
            println!("Packet type: {}", pkt.kind() as u16);
            match pkt.kind() {
                PacketType::PublicKeyNonce => {
                    let data_pkt: &HandshakePacket = interpret_packet(&pkt).as_ref().unwrap();
                    conn.add_remote_key(&data_pkt.public_key, &data_pkt.nonce);
                    println!("Server key: {:?}", conn.local_key.session.as_ref().unwrap());

                    if is_server {
                        let aad = [1, 2, 3, 4];
                        let plaintext = b"hello, world";
                        let mut ciphertext = Vec::with_capacity(plaintext.len());
                        let tag = encrypt(conn.local_key.session.as_ref().unwrap(), &conn.local_key.nonce, &aad, plaintext, &mut ciphertext).unwrap();
                        println!("encrypted: {:?} {:?}", ciphertext, tag);

                        let pkt: EncryptedPacket = EncryptedPacket {
                            tag_len: tag.len() as u16,
                            data_len: ciphertext.len() as u16,
                        };
                        let mut buf: Vec<u8>= vec![];
                        buf.extend(struct_as_slice(&pkt));
                        buf.extend(&ciphertext);
                        buf.extend(&tag);
                        let _ = write_packet(conn.stream.borrow_mut(), &buf, 0, PacketType::EncryptedData);
                    }
                },
                PacketType::AuthRequest => {},
                PacketType::EncryptedData => {
                    let (data_pkt, rest) = interpret_packet_extra::<EncryptedPacket>(&pkt).unwrap();
                    let ciphertext = &rest[..data_pkt.data_len as usize];
                    let tag = &rest[data_pkt.data_len as usize..];
                    let aad = [1, 2, 3, 4];
                    let mut plaintext = Vec::with_capacity(ciphertext.len());
                    println!("decrypting: {:?} {:?}", ciphertext, tag);
                    let _ = decrypt(conn.local_key.session.as_ref().unwrap(), &conn.remote_key.as_ref().unwrap().nonce, &aad, &ciphertext, &tag, &mut plaintext);
                    println!("decrypted: {:?}", String::from_utf8(plaintext));
                },
                PacketType::Disconnect => {},
            }
        }
    }
}


pub fn server() -> Result<(), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:9988").unwrap();
    for stream in listener.incoming() {
        let stream: TcpStream = stream.unwrap();
        let conn = ConnectionContext::new(stream);
        let _ = event_loop(conn, true);
    }
    Ok(())
}

pub fn client() -> Result<(), std::io::Error> {
    let stream = TcpStream::connect("127.0.0.1:9988").unwrap();
    let conn = ConnectionContext::new(stream);
    let _ = event_loop(conn, false);
    Ok(())
}

pub fn test() {
    thread::spawn(move || { let _ = server(); });
    let child = thread::spawn(move || { let _ = client(); });
    let _ = child.join();
}

#[cfg(test)]
mod tests {
    use crate::test;
    #[test]
    fn it_works() {
        test();
    }
}
