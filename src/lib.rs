extern crate x25519_dalek;
extern crate rand;
extern crate chacha20_poly1305_aead;

use chacha20_poly1305_aead::{encrypt,decrypt};
use x25519_dalek::generate_secret;
use x25519_dalek::generate_public;
use rand::thread_rng;

use std::collections::VecDeque;
use std::thread;
//use std::io::prelude::*;
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

use x25519_dalek::diffie_hellman;

fn struct_as_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::std::slice::from_raw_parts(
            (p as *const T) as *const u8,
            ::std::mem::size_of::<T>(),
        )
    }
}
//unsafe fn struct_as_mut_slice<T: Sized>(p: &mut T) -> &[u8] {
//    ::std::slice::from_raw_parts_mut(
//        (p as *mut T) as *mut u8,
//        ::std::mem::size_of::<T>(),
//    )
//}
//unsafe fn slice_as_struct<T: Sized>(p: &[u8]) -> Result<&T, &'static str> {
fn slice_as_struct<T>(p: &[u8]) -> Result<&T, &'static str> {
    unsafe {
        if p.len() < ::std::mem::size_of::<T>() {
            return Err("Cannot cast bytes to struct: size mismatch");
        }
        Ok(&*(&p[..::std::mem::size_of::<T>()] as *const [u8] as *const T))
    }
}
//unsafe fn slice_as_mut_struct<T: Sized>(p: &mut [u8]) -> Result<&mut T, &'static str> {
//    if p.len() < ::std::mem::size_of::<T>() {
//        return Err("Cannot cast bytes to struct: size mismatch");
//    }
//    Ok(&mut *(&mut p[..::std::mem::size_of::<T>()] as *mut [u8] as *mut T))
//}
//unsafe fn slice_as_owned_struct<T: Sized>(mut p: Box<[u8]>) -> Result<T, &'static str> {
//    if p.len() < ::std::mem::size_of::<T>() {
//        return Err("Cannot cast bytes to struct: size mismatch");
//    }
//    println!("box size: {} / T size: {}", ::std::mem::size_of_val(&*p), ::std::mem::size_of::<T>());
//    println!("p: {}", p[0]);
//    let p = Box::into_raw(p);
//    Ok(*Box::from_raw(p as *mut T))
//}
//unsafe fn vec_as_struct<T: Sized>(p: &Vec<u8>) -> Result<&T, &'static str> {
//    if p.len() < ::std::mem::size_of::<T>() {
//        return Err("Cannot cast bytes to struct: buffer too small");
//    }
//    let s = &p.as_slice()[..::std::mem::size_of::<T>()];
//    Ok(&*(s as *const [u8] as *const T))
//}

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

//#[repr(packed)]
//struct Packet<'a> {
//    header: PacketHeader,
//    data: &'a [u8],
//}
//impl <'a> Packet<'a> {
//    fn new(msg_id: u16, kind: PacketType, data: &'a [u8]) -> Packet {
//        Packet {
//            header: PacketHeader {
//                len: data.len() as u16,
//                msg_id: msg_id,
//                packet_type: kind,
//                _reserved: 0u16,
//            },
//            data: data
//        }
//    }
//}


//enum ServerConnectionState {
//    New,
//    Encrypted,
//    Authenticated,
//}
//
//struct ServerConnectionContext {
//    state: ServerConnectionState,
//    remote_public: [u8; 32],
//    nonce: [u8; 12],
//}

//pub fn read_struct<'a,T>(stream: &mut TcpStream, mut buf: &'a mut [u8]) -> Result<&'a T, &'static str> {
//    let sz = ::std::mem::size_of::<T>();
//    let buf_len = stream.read_exact(&mut buf[..sz]).unwrap();
//    let pkt: &T = unsafe { slice_as_struct(buf)? };
//    Ok(pkt)
//}
//
//pub fn read_owned_struct<'a,T>(stream: &mut TcpStream) -> Result<T, &'static str> {
//    let sz = ::std::mem::size_of::<T>();
//    let mut buf: Box<[u8]> = vec![0; sz].into_boxed_slice();
//    let buf_len = stream.read_exact(&mut buf[..sz]).unwrap();
//    let pkt: T = unsafe { slice_as_owned_struct(buf)? };
//    Ok(pkt)
//}

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

fn read_packet<T>(stream: &mut T) -> Result<NetworkPacket, std::io::Error>
where T: std::io::Read {
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

fn write_packet<T>(stream: &mut T, data: &[u8], msg_id: u16, kind: PacketType) -> Result<(), std::io::Error>
where T: std::io::Write {
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

pub fn event_loop(stream: &mut TcpStream, is_server: bool) -> Result<(), std::io::Error> {
    let mut seed = thread_rng();
    let sec_key = generate_secret(&mut seed);
    let pub_key = generate_public(&sec_key);
    println!("conn: {} {}", stream.peer_addr().unwrap(), is_server);

    //let _ = stream.write(pub_key.as_bytes());

    let mut remote_public: [u8; 32] = [0; 32];
    let mut nonce: [u8; 12] = [0; 12];
    let mut sess_key: [u8; 32] = [0; 32];

    let mut pkt: HandshakePacket = Default::default();
    pkt.public_key.copy_from_slice(pub_key.as_bytes());
    pkt.nonce.copy_from_slice(&[1,0,0,0,0,1,0,0,0,0,1,0]);
    let _ = write_packet(stream, struct_as_slice(&pkt), 0, PacketType::PublicKeyNonce);

    let mut pkt_queue: VecDeque<NetworkPacket> = VecDeque::with_capacity(20);
    loop {
        pkt_queue.push_back(read_packet(stream)?);
        if let Some(pkt) = pkt_queue.pop_front() {
            println!("Packet type: {}", pkt.kind() as u16);
            match pkt.kind() {
                PacketType::PublicKeyNonce => {
                    let data_pkt: &HandshakePacket = interpret_packet(&pkt).unwrap();
                    remote_public.copy_from_slice(&data_pkt.public_key);
                    nonce.copy_from_slice(&data_pkt.nonce);
                    sess_key = diffie_hellman(&sec_key, &remote_public);
                    println!("Server key: {:?}", sess_key);

                    if is_server {
                        let aad = [1, 2, 3, 4];
                        let plaintext = b"hello, world";
                        let mut ciphertext = Vec::with_capacity(plaintext.len());
                        let tag = encrypt(&sess_key, &nonce, &aad, plaintext, &mut ciphertext).unwrap();
                        println!("encrypted: {:?} {:?}", ciphertext, tag);

                        let pkt: EncryptedPacket = EncryptedPacket {
                            tag_len: tag.len() as u16,
                            data_len: ciphertext.len() as u16,
                        };
                        let mut buf: Vec<u8>= vec![];
                        buf.extend(struct_as_slice(&pkt));
                        buf.extend(&ciphertext);
                        buf.extend(&tag);
                        let _ = write_packet(stream, &buf, 0, PacketType::EncryptedData);
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
                    let _ = decrypt(&sess_key, &nonce, &aad, &ciphertext, &tag, &mut plaintext);
                    println!("decrypted: {:?}", String::from_utf8(plaintext));
                },
                PacketType::Disconnect => {},
            }
        }
    }
}


pub fn server2() -> Result<(), std::io::Error> {
    let listener = TcpListener::bind("127.0.0.1:9988").unwrap();
    for stream in listener.incoming() {
        let mut stream: TcpStream = stream.unwrap();
        let _ = event_loop(&mut stream, true);
    }
    Ok(())
}

pub fn client2() -> Result<(), std::io::Error> {
    let mut stream = TcpStream::connect("127.0.0.1:9988").unwrap();
    let _ = event_loop(&mut stream, false);
    Ok(())
}

//pub fn server() {
//    let listener = TcpListener::bind("127.0.0.1:9988").unwrap();
//    for stream in listener.incoming() {
//        let mut stream: TcpStream = stream.unwrap();
//        stream.set_nonblocking(false);
//
//        let mut seed = thread_rng();
//        let sec_key = generate_secret(&mut seed);
//        let pub_key = generate_public(&sec_key);
//        println!("Server conn: {}", stream.peer_addr().unwrap());
//        let _ = stream.write(pub_key.as_bytes());
//
//        let mut buf: Box<[u8]> = Box::new([0u8; 65535]);
//        {
//            let hdr: &PacketHeader = read_struct(&mut stream, &mut buf).unwrap();
//            println!("hdr len: {}", hdr.len);
//        }
//        let pkt: &HandshakePacket = read_struct(&mut stream, &mut buf).unwrap();
//        println!("pkt len: {}", pkt.len);
//        println!("Server write");
//
//        let mut remote_public: [u8; 32] = [0; 32];
//        let mut nonce: [u8; 12] = [0; 12];
//        remote_public.copy_from_slice(&pkt.public_key);
//        nonce.copy_from_slice(&pkt.nonce);
//
//        let sess_key = diffie_hellman(&sec_key, &remote_public);
//        println!("Server key: {:?}", sess_key);
//
//        let aad = [1, 2, 3, 4];
//        let plaintext = b"hello, world";
//        let mut ciphertext = Vec::with_capacity(plaintext.len());
//        let tag = encrypt(&sess_key, &nonce, &aad, plaintext, &mut ciphertext).unwrap();
//        println!("encrypted: {:?} {:?}", ciphertext, tag);
//
//        unsafe {
//            let pkt: EncryptedPacket = EncryptedPacket {
//                tag_len: tag.len() as u16,
//                data_len: ciphertext.len() as u16,
//            };
//            let pkt = Packet::new(0, PacketType::EncryptedData, struct_as_slice(&pkt));
//            //let _ = stream.write(struct_as_slice(&pkt));
//            let _ = stream.write(struct_as_slice(&pkt.header));
//            let _ = stream.write(pkt.data);
//            let _ = stream.write(&ciphertext);
//            let _ = stream.write(&tag);
//        }
//    }
//}
//
//pub fn client() {
//    let mut stream = TcpStream::connect("127.0.0.1:9988").unwrap();
//    stream.set_nonblocking(false);
//    let mut seed = thread_rng();
//    let sec_key = generate_secret(&mut seed);
//    let pub_key = generate_public(&sec_key);
//
//    let mut pkt: HandshakePacket = Default::default();
//    pkt.public_key.copy_from_slice(pub_key.as_bytes());
//    pkt.nonce.copy_from_slice(&[1,0,0,0,0,1,0,0,0,0,1,0]);
//
//    unsafe {
//        let pkt = Packet::new(0, PacketType::PublicKeyNonce, struct_as_slice(&pkt));
//        //let _ = stream.write(struct_as_slice(&pkt));
//        let _ = stream.write(struct_as_slice(&pkt.header));
//        let _ = stream.write(pkt.data);
//    }
//    //let _ = stream.write(pub_key.as_bytes());
//    println!("Client write");
//    let mut buf = vec![0u8; 4096];
//    let buf_len = stream.read(&mut buf).unwrap();
//    println!("Client read: {}", buf_len);
//    let mut remote_public: [u8; 32] = [0; 32];
//    remote_public.copy_from_slice(&buf[..32]);
//    let sess_key = diffie_hellman(&sec_key, &remote_public);
//    println!("Client key: {:?}", sess_key);
//
//    let hdr_len = {
//        let hdr: &PacketHeader = read_struct(&mut stream, &mut buf).unwrap();
//        println!("hdr len: {}", hdr.len);
//        hdr.len
//    } as usize;
//    let (tag_len, data_len) = {
//        let pkt: &EncryptedPacket = read_struct(&mut stream, &mut buf).unwrap();
//        (pkt.tag_len as usize, pkt.data_len as usize)
//    };
//    let mut tag: Vec<u8> = vec![0; tag_len];
//    let mut ciphertext: Vec<u8> = vec![0; data_len];
//    let _ = stream.read_exact(&mut ciphertext).unwrap();
//    let _ = stream.read_exact(&mut tag).unwrap();
//    let aad = [1, 2, 3, 4];
//    let mut plaintext = Vec::with_capacity(ciphertext.len());
//    println!("decrypting: {:?} {:?}", ciphertext, tag);
//    decrypt(&sess_key, &pkt.nonce, &aad, &ciphertext, &tag, &mut plaintext);
//    println!("decrypted: {:?}", String::from_utf8(plaintext));
//
//    println!("Client done");
//}

pub fn test() {
    thread::spawn(move || { let _ = server2(); });
    let child = thread::spawn(move || { let _ = client2(); });
    let _ = child.join();
    //let mut alice_csprng = thread_rng();
    //let     alice_secret = generate_secret(&mut alice_csprng);
    //let     alice_public = generate_public(&alice_secret);
    //let mut bob_csprng = thread_rng();
    //let     bob_secret = generate_secret(&mut bob_csprng);
    //let     bob_public = generate_public(&bob_secret);
    //use x25519_dalek::diffie_hellman;
    //let shared_secret_a = diffie_hellman(&alice_secret, &bob_public.as_bytes());
    //let shared_secret_b = diffie_hellman(&bob_secret, &alice_public.as_bytes());
    //let key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    //           17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
    //let nonce = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    //let aad = [1, 2, 3, 4];
    //let plaintext = b"hello, world";
    //let mut ciphertext = Vec::with_capacity(plaintext.len());
    //let tag = encrypt(&key, &nonce, &aad, plaintext, &mut ciphertext).unwrap();
    //println!("encrypted: {:?}", ciphertext);
    //let mut plaintext = Vec::with_capacity(ciphertext.len());
    //decrypt(&key, &nonce, &aad, &ciphertext, &tag, &mut plaintext);
    //println!("decrypted: {:?}", String::from_utf8(plaintext));
}

#[cfg(test)]
mod tests {
    use crate::test;
    #[test]
    fn it_works() {
        test();
    }
}
