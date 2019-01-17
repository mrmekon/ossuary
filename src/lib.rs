#![feature(test)]
#![feature(try_from)]

extern crate x25519_dalek;
extern crate ed25519_dalek;
extern crate rand;
extern crate chacha20_poly1305_aead;
extern crate sha2;

use chacha20_poly1305_aead::{encrypt,decrypt};
use x25519_dalek::generate_secret;
use x25519_dalek::generate_public;
use x25519_dalek::diffie_hellman;

use ed25519_dalek::{Signature, Keypair, SecretKey, PublicKey};
use sha2::Sha512;

//use rand::thread_rng;
use rand::RngCore;
use rand::rngs::OsRng;

use std::convert::TryInto;

pub mod clib;

// Maximum time to wait (in seconds) for a handshake response
const MAX_HANDSHAKE_WAIT_TIME: u64 = 3u64;

// Size of the random data to be signed by client
const CHALLENGE_LEN: usize = 256;

// Internal buffer for copy of network data
const PACKET_BUF_SIZE: usize = 16384
    + ::std::mem::size_of::<PacketHeader>()
    + ::std::mem::size_of::<EncryptedPacket>()
    + 16; // chacha20 tag

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

// TODO:
//  - non-blocking IO
//  - remove all unwraps()
//  - consider all unexpected packet types to be errors
//  - limit connection retries

fn struct_as_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::std::slice::from_raw_parts(
            (p as *const T) as *const u8,
            ::std::mem::size_of::<T>(),
        )
    }
}
fn slice_as_struct<T>(p: &[u8]) -> Result<&T, OssuaryError> {
    unsafe {
        if p.len() < ::std::mem::size_of::<T>() {
            return Err(OssuaryError::InvalidStruct);
        }
        Ok(&*(&p[..::std::mem::size_of::<T>()] as *const [u8] as *const T))
    }
}

pub enum OssuaryError {
    Io(std::io::Error),
    WouldBlock(usize), // bytes consumed
    Unpack(core::array::TryFromSliceError),
    KeySize(usize, usize), // (expected, actual)
    InvalidKey,
    InvalidPacket(String),
    InvalidStruct,
    InvalidSignature,
    ConnectionFailed,
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
impl From<ed25519_dalek::SignatureError> for OssuaryError {
    fn from(_error: ed25519_dalek::SignatureError) -> Self {
        OssuaryError::InvalidKey
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
    Disconnect = 0x01,
    Reset = 0x02,
    PublicKeyNonce = 0x10,
    PubKeyAck = 0x11,
    AuthChallenge = 0x12,
    AuthResponse = 0x13,
    EncryptedData = 0x20,
}
impl PacketType {
    pub fn from_u16(i: u16) -> PacketType {
        match i {
            0x01 => PacketType::Disconnect,
            0x02 => PacketType::Reset,
            0x10 => PacketType::PublicKeyNonce,
            0x11 => PacketType::PubKeyAck,
            0x12 => PacketType::AuthChallenge,
            0x13 => PacketType::AuthResponse,
            0x20 => PacketType::EncryptedData,
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
    ServerSendChallenge,
    ServerWaitAuth(std::time::SystemTime),

    ClientNew,
    ClientWaitKey(std::time::SystemTime),
    ClientSendAck,
    ClientWaitAck(std::time::SystemTime),
    ClientSendAuth,

    Failed(OssuaryError),
    Encrypted,
}
struct KeyMaterial {
    secret: Option<[u8; 32]>,
    public: [u8; 32],
    session: Option<[u8; 32]>,
    nonce: [u8; 12],
}

pub enum ConnectionType {
    Client,
    AuthenticatedServer,
    UnauthenticatedServer,
}

pub struct ConnectionContext {
    state: ConnectionState,
    conn_type: ConnectionType,
    local_key: KeyMaterial,
    remote_key: Option<KeyMaterial>,
    local_msg_id: u16,
    remote_msg_id: u16,
    challenge: Option<Vec<u8>>,
    challenge_sig: Option<Vec<u8>>,
    authorized_keys: Vec<[u8; 32]>,
    secret_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    packet_buf: [u8; PACKET_BUF_SIZE],
    packet_buf_used: usize,
}
impl ConnectionContext {
    pub fn new(conn_type: ConnectionType) -> ConnectionContext {
        //let mut rng = thread_rng();
        let mut rng = OsRng::new().expect("RNG not available.");
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
            state: match conn_type {
                ConnectionType::Client => ConnectionState::ClientNew,
                _ => ConnectionState::ServerNew,
            },
            conn_type: conn_type,
            local_key: key,
            remote_key: None,
            local_msg_id: 0u16,
            remote_msg_id: 0u16,
            challenge: None,
            challenge_sig: None,
            authorized_keys: vec!(),
            secret_key: None,
            public_key: None,
            packet_buf: [0u8; PACKET_BUF_SIZE],
            packet_buf_used: 0,
        }
    }
    fn reset_state(&mut self, permanent_err: Option<OssuaryError>) {
        self.state = match permanent_err {
            None => {
                match self.conn_type {
                    ConnectionType::Client => ConnectionState::ClientNew,
                    _ => ConnectionState::ServerNew,
                }
            },
            Some(e) => {
                ConnectionState::Failed(e)
            }
        };
        self.local_msg_id = 0;
        self.challenge = None;
        self.challenge_sig = None;
        self.remote_key = None;
    }
    fn is_server(&self) -> bool {
        match self.conn_type {
            ConnectionType::Client => false,
            _ => true,
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
        if let Some(secret) = self.local_key.secret.as_ref() {
            self.local_key.session = Some(diffie_hellman(secret, public));
        }
    }
    pub fn set_authorized_keys<'a,T>(&mut self, keys: T) -> Result<usize, OssuaryError>
    where T: std::iter::IntoIterator<Item = &'a [u8]> {
        let mut count: usize = 0;
        for key in keys {
            if key.len() != 32 {
                return Err(OssuaryError::KeySize(32, key.len()));
            }
            let mut key_owned = [0u8; 32];
            key_owned.copy_from_slice(key);
            self.authorized_keys.push(key_owned);
            count += 1;
        }
        Ok(count)
    }
    pub fn set_secret_key(&mut self, key: &[u8]) -> Result<(), OssuaryError> {
        if key.len() != 32 {
            return Err(OssuaryError::KeySize(32, key.len()));
        }
        let secret = SecretKey::from_bytes(key)?;
        let public = PublicKey::from_secret::<Sha512>(&secret);
        self.secret_key = Some(secret);
        self.public_key = Some(public);
        Ok(())
    }
    pub fn public_key(&self) -> Result<&[u8], OssuaryError> {
        match self.public_key {
            None => Err(OssuaryError::InvalidKey),
            Some(ref p) => {
                Ok(p.as_bytes())
            }
        }
    }
}

fn interpret_packet<'a, T>(pkt: &'a NetworkPacket) -> Result<&'a T, OssuaryError> {
    let s: &T = slice_as_struct(&pkt.data)?;
    Ok(s)
}

fn interpret_packet_extra<'a, T>(pkt: &'a NetworkPacket) -> Result<(&'a T, &'a [u8]), OssuaryError> {
    let s: &T = slice_as_struct(&pkt.data)?;
    Ok((s, &pkt.data[::std::mem::size_of::<T>()..]))
}

fn read_packet<T,U>(conn: &mut ConnectionContext, mut stream: T) ->Result<(NetworkPacket, usize), OssuaryError>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Read {
    let header_size = ::std::mem::size_of::<PacketHeader>();
    let bytes_read: usize;
    match stream.read(&mut conn.packet_buf[conn.packet_buf_used..]) {
        Ok(b) => bytes_read = b,
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            return Err(OssuaryError::WouldBlock(0))
        },
        Err(e) => return Err(e.into()),
    }
    conn.packet_buf_used += bytes_read;
    let buf: &[u8] = &conn.packet_buf;
    let hdr = PacketHeader {
        len: u16::from_be_bytes(buf[0..2].try_into()?),
        msg_id: u16::from_be_bytes(buf[2..4].try_into()?),
        packet_type: PacketType::from_u16(u16::from_be_bytes(buf[4..6].try_into()?)),
        _reserved: u16::from_be_bytes(buf[6..8].try_into()?),
    };
    let packet_len = hdr.len as usize;
    if conn.packet_buf_used < header_size + packet_len {
        return Err(OssuaryError::WouldBlock(bytes_read));
    }
    let buf: Box<[u8]> = (&conn.packet_buf[header_size..header_size+packet_len])
        .to_vec().into_boxed_slice();
    let excess = conn.packet_buf_used - header_size - packet_len;
    unsafe {
        // no safe way to memmove() in Rust?
        std::ptr::copy::<u8>(
            conn.packet_buf.as_ptr().offset((header_size + packet_len) as isize),
            conn.packet_buf.as_mut_ptr(),
            excess);
    }
    conn.packet_buf_used = excess;
    Ok((NetworkPacket {
        header: hdr,
        data: buf,
    },
    header_size + packet_len))
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
            // Wait for client to initiate connection
            true
        },
        ConnectionState::Encrypted => {
            // Handshake finished
            false
        },
        ConnectionState::ServerWaitAck(t) |
        ConnectionState::ServerWaitAuth(t) |
        ConnectionState::ClientWaitKey(t) |
        ConnectionState::ClientWaitAck(t) => {
            // Wait for response, with timeout
            if let Ok(dur) = t.elapsed() {
                if dur.as_secs() > MAX_HANDSHAKE_WAIT_TIME {
                    let pkt: HandshakePacket = Default::default();
                    let _ = write_packet(&mut buf, struct_as_slice(&pkt),
                                         &mut next_msg_id, PacketType::Reset);
                    conn.reset_state(None);
                }
            }
            true
        },
        ConnectionState::ServerSendPubKey => {
            // Send session public key and nonce to the client
            let mut pkt: HandshakePacket = Default::default();
            pkt.public_key.copy_from_slice(&conn.local_key.public);
            pkt.nonce.copy_from_slice(&conn.local_key.nonce);
            let _ = write_packet(&mut buf, struct_as_slice(&pkt),
                                 &mut next_msg_id, PacketType::PublicKeyNonce);
            conn.state = ConnectionState::ServerWaitAck(std::time::SystemTime::now());
            true
        },
        ConnectionState::ServerSendChallenge => {
            match conn.conn_type {
                ConnectionType::AuthenticatedServer => {
                    // Send a block of random data over the encrypted session to
                    // the client.  The client must sign it with its key to prove
                    // key possession.
                    let mut rng = match OsRng::new() {
                        Ok(rng) => rng,
                        Err(_) => {
                            conn.reset_state(None);
                            return true;
                        }
                    };
                    let aad = [];
                    let mut challenge: [u8; CHALLENGE_LEN] = [0; CHALLENGE_LEN];
                    rng.fill_bytes(&mut challenge);
                    conn.challenge = Some(challenge.to_vec());
                    let mut ciphertext = Vec::with_capacity(CHALLENGE_LEN);
                    let session_key = match conn.local_key.session {
                        Some(ref s) => s,
                        None => {
                            conn.reset_state(None);
                            return true;
                        }
                    };
                    let tag = match encrypt(session_key,
                                            &conn.local_key.nonce,
                                            &aad, &challenge, &mut ciphertext) {
                        Ok(tag) => tag,
                        Err(_) => {
                            conn.reset_state(None);
                            return true;
                        }
                    };
                    let pkt: EncryptedPacket = EncryptedPacket {
                        tag_len: tag.len() as u16,
                        data_len: ciphertext.len() as u16,
                    };
                    let mut pkt_buf: Vec<u8>= vec![];
                    pkt_buf.extend(struct_as_slice(&pkt));
                    pkt_buf.extend(&ciphertext);
                    pkt_buf.extend(&tag);
                    let _ = write_packet(&mut buf, &pkt_buf,
                                         &mut next_msg_id, PacketType::AuthChallenge);
                    conn.state = ConnectionState::ServerWaitAuth(std::time::SystemTime::now());
                    true
                },
                _ => {
                    // For unauthenticated connections, we are done.  Already encrypted.
                    let pkt: HandshakePacket = Default::default();
                    let _ = write_packet(&mut buf, struct_as_slice(&pkt),
                                         &mut next_msg_id, PacketType::PubKeyAck);
                    conn.state = ConnectionState::Encrypted;
                    false // handshake is finished (success)
                },
            }
        },
        ConnectionState::ClientNew => {
            // Send session public key and nonce to initiate connection
            let mut pkt: HandshakePacket = Default::default();
            pkt.public_key.copy_from_slice(&conn.local_key.public);
            pkt.nonce.copy_from_slice(&conn.local_key.nonce);
            let _ = write_packet(&mut buf, struct_as_slice(&pkt),
                                 &mut next_msg_id, PacketType::PublicKeyNonce);
            conn.state = ConnectionState::ClientWaitKey(std::time::SystemTime::now());
            true
        },
        ConnectionState::ClientSendAck => {
            // Acknowledge reception of server's session public key and nonce
            let pkt: HandshakePacket = Default::default();
            let _ = write_packet(&mut buf, struct_as_slice(&pkt),
                                 &mut next_msg_id, PacketType::PubKeyAck);
            conn.state = ConnectionState::ClientWaitAck(std::time::SystemTime::now());
            true
        },
        ConnectionState::ClientSendAuth => {
            // Send signature of the server's challenge back to the server,
            // along with the public part of the authentication key.  This is
            // done over the established encrypted channel.
            let secret = match conn.secret_key {
                Some(ref s) => match SecretKey::from_bytes(s.as_bytes()) {
                    Ok(s) => s, // local copy of secret key
                    Err(_) => {
                        conn.reset_state(Some(OssuaryError::InvalidKey));
                        return true;
                    }
                },
                None => {
                    conn.reset_state(Some(OssuaryError::InvalidKey));
                    return true;
                }
            };
            let public = PublicKey::from_secret::<Sha512>(&secret);
            let keypair = Keypair { secret: secret, public: public };
            let sig = match conn.challenge {
                Some(ref c) => keypair.sign::<Sha512>(c).to_bytes(),
                None => {
                    conn.reset_state(None);
                    return true;
                }
            };
            let mut pkt_data: Vec<u8> = Vec::with_capacity(CHALLENGE_LEN + 32);
            pkt_data.extend_from_slice(public.as_bytes());
            pkt_data.extend_from_slice(&sig);
            conn.challenge_sig = Some(sig.to_vec());

            let aad = [];
            let mut ciphertext = Vec::with_capacity(pkt_data.len());
            let session_key = match conn.local_key.session {
                Some(ref s) => s,
                None => {
                    conn.reset_state(None);
                    return true;
                }
            };
            let tag = match encrypt(session_key,
                                    &conn.local_key.nonce,
                                    &aad, &pkt_data, &mut ciphertext) {
                Ok(t) => t,
                Err(_) => {
                    conn.reset_state(None);
                    return true;
                }
            };

            let pkt: EncryptedPacket = EncryptedPacket {
                tag_len: tag.len() as u16,
                data_len: ciphertext.len() as u16,
            };
            let mut pkt_buf: Vec<u8>= vec![];
            pkt_buf.extend(struct_as_slice(&pkt));
            pkt_buf.extend(&ciphertext);
            pkt_buf.extend(&tag);
            let _ = write_packet(&mut buf, &pkt_buf,
                                 &mut next_msg_id, PacketType::AuthResponse);
            conn.state = ConnectionState::Encrypted;
            false // handshake is finished (success)
        },
        ConnectionState::Failed(_) => {
            // This is a permanent failure.
            let pkt: HandshakePacket = Default::default();
            let _ = write_packet(&mut buf, struct_as_slice(&pkt),
                                 &mut next_msg_id, PacketType::Disconnect);
            conn.reset_state(Some(OssuaryError::ConnectionFailed));
            false // handshake is finished (failed)
        },
    };
    conn.local_msg_id = next_msg_id;
    // TODO: either this should return amount write, or send_data() should not
    more
}

// TODO u16 should be usize
pub fn crypto_recv_handshake<T,U>(conn: &mut ConnectionContext, buf: T) -> Result<usize, OssuaryError>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Read {
    // TODO: read_exact won't work.
    let mut bytes_read: usize = 0;
    let pkt: NetworkPacket = match read_packet(conn, buf) {
        Ok((p, r)) => {
            bytes_read += r;
            p
        },
        Err(OssuaryError::WouldBlock(b)) => {
            return Err(OssuaryError::WouldBlock(b));
        }
        Err(e) => {
            return Err(e);
        }
    };

    if pkt.header.msg_id != conn.remote_msg_id {
        println!("Message gap detected.  Restarting connection.");
        println!("Server: {}", conn.is_server());
        conn.reset_state(None);
        return Err(OssuaryError::InvalidPacket("Message ID does not match".into()));
    }
    conn.remote_msg_id = pkt.header.msg_id + 1;

    let mut error = false;
    match pkt.kind() {
        PacketType::Reset => {
            conn.reset_state(None);
            return Err(OssuaryError::ConnectionFailed);
        },
        PacketType::Disconnect => {
            // TODO: handle error
            conn.reset_state(Some(OssuaryError::ConnectionFailed));
            panic!("Remote side terminated connection.");
        },
        _ => {},
    }

    match conn.state {
        ConnectionState::ServerNew => {
            match pkt.kind() {
                PacketType::PublicKeyNonce => {
                    let data_pkt: Result<&HandshakePacket, _> = interpret_packet(&pkt);
                    match data_pkt {
                        Ok(ref data_pkt) => {
                            conn.add_remote_key(&data_pkt.public_key, &data_pkt.nonce);
                            conn.state = ConnectionState::ServerSendPubKey;
                        },
                        Err(_) => {
                            error = true;
                        },
                    }
                },
                _ => { error = true; }
            }
        },
        ConnectionState::ServerWaitAck(_t) => {
            match pkt.kind() {
                PacketType::PubKeyAck => {
                    conn.state = ConnectionState::ServerSendChallenge;
                },
                _ => { error = true; }
            }
        },
        ConnectionState::ServerWaitAuth(_t) => {
            match pkt.kind() {
                PacketType::AuthResponse => {
                    match interpret_packet_extra::<EncryptedPacket>(&pkt) {
                        Ok((data_pkt, rest)) => {
                            let ciphertext = &rest[..data_pkt.data_len as usize];
                            let tag = &rest[data_pkt.data_len as usize..];
                            let aad = [];
                            let mut plaintext = Vec::with_capacity(ciphertext.len());
                            let session_key = match conn.local_key.session {
                                Some(ref k) => k,
                                None => {
                                    conn.reset_state(None);
                                    return Err(OssuaryError::InvalidKey);
                                }
                            };
                            let remote_nonce = match conn.remote_key {
                                Some(ref rem) => rem.nonce,
                                None => {
                                    conn.reset_state(None);
                                    return Err(OssuaryError::InvalidKey);
                                }
                            };
                            let _ = decrypt(session_key,
                                            &remote_nonce,
                                            &aad, &ciphertext, &tag, &mut plaintext);
                            let pubkey = &plaintext[0..32];
                            let sig = &plaintext[32..];
                            if conn.authorized_keys.iter().filter(|k| &pubkey == k).count() > 0 {
                                let public = match PublicKey::from_bytes(pubkey) {
                                    Ok(p) => p,
                                    Err(_) => {
                                        conn.reset_state(None);
                                        return Err(OssuaryError::InvalidKey);
                                    }
                                };
                                let sig = match Signature::from_bytes(sig) {
                                    Ok(s) => s,
                                    Err(_) => {
                                        conn.reset_state(None);
                                        return Err(OssuaryError::InvalidKey);
                                    }
                                };
                                let challenge = match conn.challenge {
                                    Some(ref c) => c,
                                    None => {
                                        conn.reset_state(None);
                                        return Err(OssuaryError::InvalidKey);
                                    }
                                };
                                match public.verify::<Sha512>(challenge, &sig) {
                                    Ok(_) => {
                                        conn.state = ConnectionState::Encrypted;
                                    },
                                    Err(_) => {
                                        println!("Verify bad");
                                        conn.state = ConnectionState::Failed(
                                            OssuaryError::InvalidSignature);
                                    },
                                }
                            }
                            else {
                                println!("Key not allowed");
                                conn.state = ConnectionState::Failed(OssuaryError::InvalidKey);
                            }
                        },
                        Err(_) => {
                            conn.reset_state(None);
                            return Err(OssuaryError::InvalidPacket("Response invalid".into()));
                        },
                    };
                },
                _ => { error = true; }
            }
        },
        ConnectionState::ServerSendPubKey => {
            error = true;
        }, // nop
        ConnectionState::ServerSendChallenge => {
            error = true;
        }, // nop
        ConnectionState::ClientNew => {
            error = true;
        }, // nop
        ConnectionState::ClientWaitKey(_t) => {
            match pkt.kind() {
                PacketType::PublicKeyNonce => {
                    let data_pkt: Result<&HandshakePacket, _> = interpret_packet(&pkt);
                    match data_pkt {
                        Ok(data_pkt) => {
                            conn.add_remote_key(&data_pkt.public_key, &data_pkt.nonce);
                            conn.state = ConnectionState::ClientSendAck;
                        },
                        Err(_) => {
                            error = true;
                        },
                    }
                },
                _ => {
                    error = true;
                }
            }
        },
        ConnectionState::ClientSendAck => {
            error = true;
        }, // nop
        ConnectionState::ClientWaitAck(_t) => {
            match pkt.kind() {
                PacketType::PubKeyAck => {
                    conn.state = ConnectionState::Encrypted;
                },
                PacketType::AuthChallenge => {
                    match interpret_packet_extra::<EncryptedPacket>(&pkt) {
                        Ok((data_pkt, rest)) => {
                            let ciphertext = &rest[..data_pkt.data_len as usize];
                            let tag = &rest[data_pkt.data_len as usize..];
                            let aad = [];
                            let mut plaintext = Vec::with_capacity(ciphertext.len());

                            let session_key = match conn.local_key.session {
                                Some(ref k) => k,
                                None => {
                                    conn.reset_state(None);
                                    return Err(OssuaryError::InvalidKey);
                                }
                            };
                            let remote_nonce = match conn.remote_key {
                                Some(ref rem) => rem.nonce,
                                None => {
                                    conn.reset_state(None);
                                    return Err(OssuaryError::InvalidKey);
                                }
                            };
                            let _ = decrypt(session_key,
                                            &remote_nonce,
                                            &aad, &ciphertext, &tag, &mut plaintext);
                            conn.challenge = Some(plaintext);
                            conn.state = ConnectionState::ClientSendAuth;
                        },
                        Err(_) => {
                            error = true;
                        },
                    }
                },
                _ => {
                    error = true;
                },
            }
        },
        ConnectionState::ClientSendAuth => {
            error = true;
        }, // nop
        ConnectionState::Failed(_) => {
            error = true;
        }, // nop
        ConnectionState::Encrypted => {
            error = true;
        }, // nop
    }
    if error {
        conn.reset_state(None);
    }
    Ok(bytes_read)
}

// TODO: should return a Result with error on forced-disconnect or permanent failure
pub fn crypto_handshake_done(conn: &ConnectionContext) -> Result<bool, &OssuaryError> {
    match conn.state {
        ConnectionState::Encrypted => Ok(true),
        ConnectionState::Failed(ref e) => Err(e),
        _ => Ok(false),
    }
}

pub fn crypto_send_data<T,U>(conn: &mut ConnectionContext, in_buf: &[u8], mut out_buf: T) -> Result<u16, OssuaryError>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Write {
    match conn.state {
        ConnectionState::Encrypted => {},
        _ => {
            return Err(OssuaryError::InvalidPacket("Encrypted channel not established.".into()));
        }
    }
    let mut next_msg_id = conn.local_msg_id;
    let bytes;
    let aad = [];
    let mut ciphertext = Vec::with_capacity(in_buf.len());
    let session_key = match conn.local_key.session {
        Some(ref k) => k,
        None => {
            conn.reset_state(None);
            return Err(OssuaryError::InvalidKey);;
        }
    };
    let tag = match encrypt(session_key,
                            &conn.local_key.nonce, &aad, in_buf, &mut ciphertext) {
        Ok(t) => t,
        Err(_) => {
            conn.reset_state(None);
            return Err(OssuaryError::InvalidKey);;
        }
    };

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
    bytes = (buf.len() + ::std::mem::size_of::<PacketHeader>()) as u16;
    conn.local_msg_id = next_msg_id;
    Ok(bytes)
}

pub fn crypto_recv_data<T,U,R,V>(conn: &mut ConnectionContext, in_buf: T, mut out_buf: R) -> Result<(u16, u16), OssuaryError>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Read,
      R: std::ops::DerefMut<Target = V>,
      V: std::io::Write {
    let bytes_written: u16;
    let mut bytes_read: u16 = 0u16;
    match conn.state {
        ConnectionState::Encrypted => {},
        _ => {
            return Err(OssuaryError::InvalidPacket("Encrypted channel not established.".into()));
        }
    }

    match read_packet(conn, in_buf) {
        Ok((pkt, bytes)) => {
            bytes_read += bytes as u16;
            if pkt.header.msg_id != conn.remote_msg_id {
                println!("Message gap detected.  Restarting connection.");
                println!("Server: {}", conn.is_server());
                conn.reset_state(None);
                return Err(OssuaryError::InvalidPacket("Message ID mismatch".into()))
            }
            conn.remote_msg_id = pkt.header.msg_id + 1;

            match pkt.kind() {
                PacketType::EncryptedData => {
                    match interpret_packet_extra::<EncryptedPacket>(&pkt) {
                        Ok((data_pkt, rest)) => {
                            let ciphertext = &rest[..data_pkt.data_len as usize];
                            let tag = &rest[data_pkt.data_len as usize..];
                            let aad = [];
                            let mut plaintext = Vec::with_capacity(ciphertext.len());
                            let session_key = match conn.local_key.session {
                                Some(ref k) => k,
                                None => {
                                    conn.reset_state(None);
                                    return Err(OssuaryError::InvalidKey);
                                }
                            };
                            let remote_nonce = match conn.remote_key {
                                Some(ref rem) => rem.nonce,
                                None => {
                                    conn.reset_state(None);
                                    return Err(OssuaryError::InvalidKey);
                                }
                            };
                            let _ = decrypt(session_key,
                                            &remote_nonce,
                                            &aad, &ciphertext, &tag, &mut plaintext);
                            let _ = out_buf.write(&plaintext);
                            bytes_written = ciphertext.len() as u16;
                        },
                        Err(_) => {
                            conn.reset_state(None);
                            return Err(OssuaryError::InvalidKey);
                        },
                    }
                },
                _ => {
                    return Err(OssuaryError::InvalidPacket("Received non-encrypted data on encrypted channel.".into()));
                },
            }
        },
        Err(OssuaryError::WouldBlock(b)) => {
            return Err(OssuaryError::WouldBlock(b));
        },
        Err(_e) => {
            return Err(OssuaryError::InvalidPacket("Packet header did not parse.".into()));
        },
    }
    Ok((bytes_read, bytes_written))
}

#[cfg(test)]
mod tests {
    extern crate test;
    use test::Bencher;
    use std::thread;
    use std::net::{TcpListener, TcpStream};
    use crate::*;

    #[test]
    fn test_set_authorized_keys() {
        let mut conn = ConnectionContext::new(ConnectionType::AuthenticatedServer);

        // Vec of slices
        let keys: Vec<&[u8]> = vec![
            &[0xbe, 0x1c, 0xa0, 0x74, 0xf4, 0xa5, 0x8b, 0xbb,
              0xd2, 0x62, 0xa7, 0xf9, 0x52, 0x3b, 0x6f, 0xb0,
              0xbb, 0x9e, 0x86, 0x62, 0x28, 0x7c, 0x33, 0x89,
              0xa2, 0xe1, 0x63, 0xdc, 0x55, 0xde, 0x28, 0x1f]
        ];
        let _ = conn.set_authorized_keys(keys).unwrap();

        // Vec of owned arrays
        let keys: Vec<[u8; 32]> = vec![
            [0xbe, 0x1c, 0xa0, 0x74, 0xf4, 0xa5, 0x8b, 0xbb,
             0xd2, 0x62, 0xa7, 0xf9, 0x52, 0x3b, 0x6f, 0xb0,
             0xbb, 0x9e, 0x86, 0x62, 0x28, 0x7c, 0x33, 0x89,
             0xa2, 0xe1, 0x63, 0xdc, 0x55, 0xde, 0x28, 0x1f]
        ];
        let _ = conn.set_authorized_keys(keys.iter().map(|x| x.as_ref()).collect::<Vec<&[u8]>>()).unwrap();

        // Vec of vecs
        let keys: Vec<Vec<u8>> = vec![
            vec![0xbe, 0x1c, 0xa0, 0x74, 0xf4, 0xa5, 0x8b, 0xbb,
                 0xd2, 0x62, 0xa7, 0xf9, 0x52, 0x3b, 0x6f, 0xb0,
                 0xbb, 0x9e, 0x86, 0x62, 0x28, 0x7c, 0x33, 0x89,
                 0xa2, 0xe1, 0x63, 0xdc, 0x55, 0xde, 0x28, 0x1f]
        ];
        let _ = conn.set_authorized_keys(keys.iter().map(|x| x.as_slice())).unwrap();
    }

    #[bench]
    fn bench_test(b: &mut Bencher) {
        let server_thread = thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:9987").unwrap();
            let mut server_stream = listener.incoming().next().unwrap().unwrap();
            let mut server_conn = ConnectionContext::new(ConnectionType::UnauthenticatedServer);
            while crypto_handshake_done(&server_conn).unwrap() == false {
                if crypto_send_handshake(&mut server_conn, &mut server_stream) {
                    loop {
                        match crypto_recv_handshake(&mut server_conn, &mut server_stream) {
                            Ok(_) => break,
                            Err(OssuaryError::WouldBlock(_)) => {},
                            _ => panic!("Handshake failed"),
                        }
                    }
                }
            }
            let mut plaintext = vec!();
            let mut bytes: u64 = 0;
            let start = std::time::SystemTime::now();
            loop {
                match crypto_recv_data(&mut server_conn,
                                       &mut server_stream,
                                       &mut plaintext) {
                    Ok((read, _written)) => bytes += read as u64,
                    Err(OssuaryError::WouldBlock(_)) => continue,
                    _ => panic!("Recv failed"),
                }
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

        std::thread::sleep(std::time::Duration::from_millis(500));
        let mut client_stream = TcpStream::connect("127.0.0.1:9987").unwrap();
        client_stream.set_nonblocking(true).unwrap();
        let mut client_conn = ConnectionContext::new(ConnectionType::Client);
        while crypto_handshake_done(&client_conn).unwrap() == false {
            if crypto_send_handshake(&mut client_conn, &mut client_stream) {
                loop {
                    match crypto_recv_handshake(&mut client_conn, &mut client_stream) {
                        Ok(_) => break,
                        Err(OssuaryError::WouldBlock(_)) => {},
                        _ => panic!("Handshake failed"),
                    }
                }
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
        drop(client_stream); // flush the buffer
        let _ = server_thread.join();
    }
}
