#![feature(try_from)]
//! # Ossuary
//!
//! Ossuary is a library for establishing an encrypted and authenticated
//! communication channel between a client and a server.
//!
//! The protocol (authenticated):
//!
//! <client> --> [session public key, session nonce] --> <server>
//! <client> <-- [session public key, session nonce] <-- <server>
//! <client> --> [ack] --> <server>
//! <client> <-- [[random challenge]] <-- <server>
//! <client> --> [[signed challenge]] --> <server>
//!
//! The protocol (unauthenticated):
//!
//! <client> --> [session public key, session nonce] --> <server>
//! <client> <-- [session public key, session nonce] <-- <server>
//! <client> --> [ack] --> <server>
//! <client> <-- [ack] <-- <server>
//!
//!
//!
//! TODO:
//! <client> --> [session x25519 public key,
//!               session nonce,
//!               client random challenge]      --> <server>
//! <client> <-- [session x25519 public key,
//!               session nonce],
//!              [[server x25519 public key,
//!                server random challenge,
//!                client challenge signature]] <-- <server>
//! <client> --> [[client x25519 public key,
//!                server challenge signature]] --> <server>
//!

//
// TODO:
//  - rename to OssuaryConnection
//  - server certificate
//  - consider all unexpected packet types to be errors
//  - ensure that a reset on one end always sends a reset to the other
//  - limit connection retries
//  - protocol version number
//  - tests should check their received strings
//  - rustdoc everything
//  - don't use HandshakePacket for multiple purposes
//
// TODO: raise OssuaryError::UntrustedServer() when trust-on-first-use

pub mod clib;

extern crate x25519_dalek;
extern crate ed25519_dalek;
extern crate rand;
extern crate chacha20_poly1305_aead;

use std::convert::TryInto;

use chacha20_poly1305_aead::{encrypt,decrypt};
use x25519_dalek::{EphemeralSecret, EphemeralPublic, SharedSecret};
use ed25519_dalek::{Signature, Keypair, SecretKey, PublicKey};

//use rand::thread_rng;
use rand::RngCore;
use rand::rngs::OsRng;

const PROTOCOL_VERSION: u8 = 1u8;

// Maximum time to wait (in seconds) for a handshake response
const MAX_HANDSHAKE_WAIT_TIME: u64 = 3u64;

// Size of the random data to be signed by client
const CHALLENGE_LEN: usize = 32;

const SIGNATURE_LEN: usize = 64;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;   // chacha20 tag

// Internal buffer for copy of network data
const PACKET_BUF_SIZE: usize = 16384
    + ::std::mem::size_of::<PacketHeader>()
    + ::std::mem::size_of::<EncryptedPacket>()
    + TAG_LEN;

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

/// Error produced by Ossuary or one of its dependencies
pub enum OssuaryError {
    /// A problem with I/O read or writes.
    ///
    /// An Io error is most likely raised when using an input or output buffer
    /// that is more complex than a simple in-memory buffer, such as a
    /// [`std::net::TcpStream`]
    Io(std::io::Error),

    /// A buffer cannot complete a read/write without blocking.
    ///
    /// Ossuary is inherently a non-blocking library, and returns this error any
    /// time it is unable to read or write more data.
    ///
    /// When using a buffer configured for non-blocking operation, such as a
    /// [`std::net::TcpStream`], any non-blocking errors
    /// ([`std::io::ErrorKind::WouldBlock`]) encounted by the buffer are raised
    /// as this error.
    ///
    /// The error has a paired parameter indicating whether any data WAS read
    /// or written (depending on the function called).  This can be non-zero
    /// on operations that require multiple consecutive read/write operations
    /// to the buffer if some but not all operations succeeded.
    ///
    /// When using an input or output buffer in a manner that requires manually
    /// sending or clearing data from the buffer, such as when passing the data
    /// from Ossuary through an in-memory buffer prior to handing it to a TCP
    /// connection, the amount of bytes indicated by the paired parameter should
    /// be processed immediately.
    WouldBlock(usize), // bytes consumed

    /// Error casting received bytes to a primitive type.
    ///
    /// This error likely indicates a sync or corruption error in the data
    /// stream, and will trigger a connection reset.
    Unpack(core::array::TryFromSliceError),

    /// An invalid sized encryption key was encountered.
    ///
    /// This error is most likely caused by an attempt to register an invalid
    /// secret or public key in [`OssuaryContext::set_authorized_keys`] or
    /// [`OssuaryContext::set_secret_key`].  Both should be 32 bytes.
    KeySize(usize, usize), // (expected, actual)

    /// An error occurred when parsing or using an encryption key.
    ///
    /// This error indicates a problem when using an encryption key.  This could
    /// be because an expected key is missing, the format is incorrect, it was
    /// corrupted in memory or in transit, or the wrong key was used.
    ///
    /// This typically indicates an internal error, and will cause the
    /// connection to reset.
    InvalidKey,

    /// The channel received an unexpected or malformed packet
    ///
    /// The associated string may describe the problem that went wrong.  This
    /// might be encountered if packets are duplicated, dropped, or corrupted.
    /// It typically indicates an internal error, and the connection will reset.
    InvalidPacket(String),

    /// Error casting a received packet to an internal struct format.
    ///
    /// This means a packet header was not found or corrupted, and will trigger
    /// a connection reset.
    InvalidStruct,

    /// The signature received from a client failed to verify.
    ///
    /// This either indicates a key mismatch (public and secret keys are not
    /// a valid pair), corruption in the stream, or a problem during the
    /// handshake.  The connection will reset.
    InvalidSignature,

    /// The connection has reset, and reconnection may be possible.
    ///
    /// Ossuary does not attempt to recover from errors encountered on the data
    /// stream.  If anything has gone wrong, it resets the connection.  When one
    /// side resets, it always tells the other side to reset as well.
    ///
    /// This error indicates that whatever went wrong may have been a temporal
    /// fluke, such as momentary corruption or a sync error.  Reconnection with
    /// the same context may be possible.  This must be handled by returning to
    /// the handshake loop.
    ConnectionReset,

    /// The connection has reset, and reconnection is not suggested.
    ///
    /// This indicates that an error has occurred that Ossuary suspects is
    /// permanent, and that a reconnect will not succeed.  Errors include
    /// failed authorization, such as a connection attempt fro a client whose
    /// public key is not authorized.
    ///
    /// When one side fails, it attempts to trigger a failure on the other side
    /// as well.
    ConnectionFailed,
}
impl std::fmt::Debug for OssuaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OssuaryError::Io(e) => write!(f, "OssuaryError::Io {}", e),
            OssuaryError::WouldBlock(_) => write!(f, "OssuaryError::WouldBlock"),
            OssuaryError::Unpack(_) => write!(f, "OssuaryError::Unpack"),
            OssuaryError::KeySize(_,_) => write!(f, "OssuaryError::KeySize"),
            OssuaryError::InvalidKey => write!(f, "OssuaryError::InvalidKey"),
            OssuaryError::InvalidPacket(_) => write!(f, "OssuaryError::InvalidPacket"),
            OssuaryError::InvalidStruct => write!(f, "OssuaryError::InvalidStruct"),
            OssuaryError::InvalidSignature => write!(f, "OssuaryError::InvalidSignature"),
            OssuaryError::ConnectionReset => write!(f, "OssuaryError::ConnectionReset"),
            OssuaryError::ConnectionFailed => write!(f, "OssuaryError::ConnectionFailed"),
        }
    }
}
impl From<std::io::Error> for OssuaryError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::WouldBlock => OssuaryError::WouldBlock(0),
            _ => OssuaryError::Io(error),
        }
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
impl From<chacha20_poly1305_aead::DecryptError> for OssuaryError {
    fn from(_error: chacha20_poly1305_aead::DecryptError) -> Self {
        OssuaryError::InvalidKey
    }
}

/// Represents the packet sent during client/server handshaking to exchange
/// ephemeral session public keys and random nonces.
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

#[repr(C,packed)]
struct ClientHandshakePacket {
    len: u16,
    version: u8,
    _reserved: [u8; 5],
    public_key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    challenge: [u8; CHALLENGE_LEN],
}
impl Default for ClientHandshakePacket {
    fn default() -> ClientHandshakePacket {
        ClientHandshakePacket {
            len: (CHALLENGE_LEN + NONCE_LEN + KEY_LEN + 8) as u16,
            version: PROTOCOL_VERSION,
            _reserved: [0u8; 5],
            public_key: [0u8; KEY_LEN],
            nonce: [0u8; NONCE_LEN],
            challenge: [0u8; CHALLENGE_LEN],
        }
    }
}
impl ClientHandshakePacket {
    fn new(pubkey: &[u8], nonce: &[u8], challenge: &[u8]) -> ClientHandshakePacket {
        let mut pkt: ClientHandshakePacket = Default::default();
        pkt.public_key.copy_from_slice(pubkey);
        pkt.nonce.copy_from_slice(nonce);
        pkt.challenge.copy_from_slice(challenge);
        pkt
    }
    fn from_packet(pkt: &NetworkPacket) -> Result<&ClientHandshakePacket, OssuaryError> {
        let hs_pkt = interpret_packet::<ClientHandshakePacket>(&pkt);
        // TODO: validate len/version fields
        hs_pkt
    }
}

#[repr(C,packed)]
struct ClientEncryptedHandshakePacket {
    public_key: [u8; KEY_LEN],
    signature: [u8; SIGNATURE_LEN],
}

#[repr(C,packed)]
struct ServerHandshakePacket {
    len: u16,
    version: u8,
    _reserved: [u8; 5],
    public_key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    subpacket: [u8; ::std::mem::size_of::<ServerEncryptedHandshakePacket>() + TAG_LEN],
}
#[repr(C,packed)]
struct ServerEncryptedHandshakePacket {
    public_key: [u8; KEY_LEN],
    challenge: [u8; CHALLENGE_LEN],
    signature: [u8; SIGNATURE_LEN],
}
impl Default for ServerEncryptedHandshakePacket {
    fn default() -> ServerEncryptedHandshakePacket {
        ServerEncryptedHandshakePacket {
            public_key: [0u8; KEY_LEN],
            challenge: [0u8; CHALLENGE_LEN],
            signature: [0u8; SIGNATURE_LEN],
        }
    }
}
fn encrypt_to_bytes<T,U>(session_key: &[u8], nonce: &[u8],
                         data: &[u8], mut out: T) -> Result<usize, OssuaryError>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Write {
    let aad = [];
    let mut ciphertext = Vec::with_capacity(data.len());
    let tag = match encrypt(session_key,
                            nonce,
                            &aad,
                            data,
                            &mut ciphertext) {
        Ok(t) => t,
        Err(_) => {
            return Err(OssuaryError::InvalidKey);
        }
    };
    let pkt: EncryptedPacket = EncryptedPacket {
        tag_len: tag.len() as u16,
        data_len: ciphertext.len() as u16,
    };
    let mut size = 0;
    size += out.write(struct_as_slice(&pkt))?;
    size += out.write(&ciphertext)?;
    size += out.write(&tag)?;
    Ok(size)
}

impl Default for ServerHandshakePacket {
    fn default() -> ServerHandshakePacket {
        ServerHandshakePacket {
            len: (NONCE_LEN + KEY_LEN + KEY_LEN + CHALLENGE_LEN + SIGNATURE_LEN + TAG_LEN + 8) as u16,
            version: PROTOCOL_VERSION,
            _reserved: [0u8; 5],
            public_key: [0u8; KEY_LEN],
            nonce: [0u8; NONCE_LEN],
            subpacket: [0; ::std::mem::size_of::<ServerEncryptedHandshakePacket>() + TAG_LEN],
        }
    }
}
impl ServerHandshakePacket {
    fn new(session_pubkey: &[u8], nonce: &[u8], session_privkey: &[u8],
           server_pubkey: &[u8], challenge: &[u8], signature: &[u8]) -> ServerHandshakePacket {
        let mut pkt: ServerHandshakePacket = Default::default();
        let mut enc_pkt: ServerEncryptedHandshakePacket = Default::default();
        pkt.public_key.copy_from_slice(session_pubkey);
        pkt.nonce.copy_from_slice(nonce);
        enc_pkt.public_key.copy_from_slice(server_pubkey);
        enc_pkt.challenge.copy_from_slice(challenge);
        enc_pkt.signature.copy_from_slice(signature);
        let mut subpkt: &mut [u8] = &mut pkt.subpacket;
        encrypt_to_bytes(session_privkey, nonce, struct_as_slice(&enc_pkt), &mut subpkt);
        pkt
    }
}

/// The packet types used by the Ossuary protocol.
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
enum PacketType {
    /// Should never be encountered.
    Unknown = 0x00,
    /// Tell other side of connection to disconnect permanently.
    Disconnect = 0x01,
    /// Tell other side to reset connection, but re-handshaking is allowed.
    Reset = 0x02,
    /// Packet containing ephemeral session public key and nonce.
    PublicKeyNonce = 0x10,
    /// Acknowledgement of receiving session public key/nonce
    PubKeyAck = 0x11,
    /// Request for an authentication signature on a given random challenge
    AuthChallenge = 0x12,
    /// Authentication response with a public key and signed challenge
    AuthResponse = 0x13,
    /// Encrypted data packet
    EncryptedData = 0x20,

    ClientHandshake = 0x30,
    ServerHandshake = 0x31,
}
impl PacketType {
    /// Convert u16 integer to a PacketType enum
    fn from_u16(i: u16) -> PacketType {
        match i {
            0x01 => PacketType::Disconnect,
            0x02 => PacketType::Reset,
            0x10 => PacketType::PublicKeyNonce,
            0x11 => PacketType::PubKeyAck,
            0x12 => PacketType::AuthChallenge,
            0x13 => PacketType::AuthResponse,
            0x20 => PacketType::EncryptedData,
            0x30 => PacketType::ClientHandshake,
            0x31 => PacketType::ServerHandshake,
            _ => PacketType::Unknown,
        }
    }
}

/// Header prepended to the front of all encrypted data packets.
#[repr(C,packed)]
struct EncryptedPacket {
    /// Length of the data (not including this header or HMAC tag)
    data_len: u16,
    /// Length of HMAC tag following the data
    tag_len: u16,
}

/// Header prepended to the front of all packets, regardless of encryption.
#[repr(C,packed)]
struct PacketHeader {
    /// Length of packet (not including this header)
    len: u16,
    /// Monotonically increasing message ID.
    msg_id: u16,
    /// The type of packet being sent.
    packet_type: PacketType,
    /// Reserved for future use.
    _reserved: u16,
}

/// Internal struct for holding a complete network packet
struct NetworkPacket {
    header: PacketHeader,
    /// Data.  If encrypted, also EncryptedPacket header and HMAC tag.
    data: Box<[u8]>,
}
impl NetworkPacket {
    fn kind(&self) -> PacketType {
        self.header.packet_type
    }
}

/// Internal state of OssuaryContext state machine.
#[derive(Debug)]
enum ConnectionState {
    /// Idle server witing for a connection
    ServerNew,
//    /// Server will send session public key and nonce next
//    ServerSendPubKey,
//    /// Server is waiting for an acknowledgement of its pubkey/nonce
//    ServerWaitAck(std::time::SystemTime),
//    /// Server will send an authentication challenge next
//    ServerSendChallenge,
//    /// Server waiting for a signed authentication response
//    ServerWaitAuth(std::time::SystemTime),

    /// Client will send a session public key and nonce next
    ClientNew,
//    /// Client waiting for pubkey/nonce from server
//    ClientWaitKey(std::time::SystemTime),
//    /// Client will send a pubkey/nonce acknowledgement next
//    ClientSendAck,
//    /// Client waiting for connection success or authentication challenge
//    ClientWaitAck(std::time::SystemTime),
//    /// Client will send a signed authentication response next
//    ClientSendAuth,

    /// Connection has failed because of the associated error.
    Failed(OssuaryError),

    /// Server is waiting for handshake packet from a client
    ///
    /// Matching client state: ClientSendHandshake
    /// Next server state: ServerSendHandshake
    ServerWaitHandshake(std::time::SystemTime),
    ServerSendHandshake,
    ServerWaitAuthentication(std::time::SystemTime),

    ClientSendHandshake,
    ClientWaitHandshake(std::time::SystemTime),
    ClientSendAuthentication,

    /// Connection is established, encrypted, and optionally authenticated.
    Encrypted,
}

struct KeyMaterial {
    secret: Option<EphemeralSecret>,
    public: [u8; 32],
    session: Option<SharedSecret>,
    nonce: [u8; 12],
}
impl Default for KeyMaterial {
    fn default() -> Self {
        KeyMaterial {
            secret: None,
            session: None,
            public: [0u8; KEY_LEN],
            nonce: [0u8; NONCE_LEN],
        }
    }
}

/// Enum specifying the client or server role of a [`OssuaryContext`]
#[derive(Clone)]
pub enum ConnectionType {
    /// This context is a client
    Client,

    /// This context is a server that requires authentication.
    ///
    /// Authenticated servers only allow connections from clients with secret
    /// keys set using [`OssuaryContext::set_secret_key`], and with the
    /// matching public key registered with the server using
    /// [`OssuaryContext::set_authorized_keys`].
    AuthenticatedServer,

    /// This context is a server that does not support authentication.
    ///
    /// Unauthenticated servers allow any client to connect, and skip the
    /// authentication stages of the handshake.  This can be used for services
    /// that are open to the public, but still want to prevent snooping or
    /// man-in-the-middle attacks by using an encrypted channel.
    UnauthenticatedServer,
}

/// Context for interacting with an encrypted communication channel
///
/// All interaction with ossuary's encrypted channels is performed via a
/// OssuaryContext instance.  It holds all of the state required to maintain
/// one side of an encrypted connection.
///
/// A context is created with [`OssuaryContext::new`], passing it a
/// [`ConnectionType`] identifying whether it is to act as a client or server.
/// Server contexts can optionally require authentication, verified by providing
/// a list of public keys of permitted clients with
/// [`OssuaryContext::set_authorized_keys`].  Clients, on the other hand,
/// authenticate by setting their secret key with
/// [`OssuaryContext::set_secret_key`].
///
/// A server must create one OssuaryContext per connected client.  Multiple
/// connections cannot be multiplexed in one context.
///
/// A OssuaryContext keeps temporary buffers for both received and soon-to-be
/// transmitted data.  This means they are not particularly small objects, but
/// in exchange they can read and write from/to streams set in non-blocking mode
/// without blocking single-threaded applications.
///
pub struct OssuaryContext {
    state: ConnectionState,
    conn_type: ConnectionType,
    local_key: KeyMaterial, // session key
    remote_key: Option<KeyMaterial>, // session key
    local_msg_id: u16,
    remote_msg_id: u16,
    local_challenge: [u8; CHALLENGE_LEN],
    remote_challenge: Option<[u8; CHALLENGE_LEN]>,
    //challenge: Option<Vec<u8>>,
    //challenge_sig: Option<Vec<u8>>,
    authorized_keys: Vec<[u8; 32]>,
    // TODO: secret key should be stored in a single spot on the heap and
    // cleared after use.  Perhaps use clear_on_drop crate.
    secret_key: Option<SecretKey>, // authentication key
    public_key: Option<PublicKey>, // authentication key
    read_buf: [u8; PACKET_BUF_SIZE],
    read_buf_used: usize,
    write_buf: [u8; PACKET_BUF_SIZE],
    write_buf_used: usize,
}
impl Default for OssuaryContext {
    fn default() -> Self {
        OssuaryContext {
            state: ConnectionState::ClientNew,
            conn_type: ConnectionType::Client,
            local_key: Default::default(),
            remote_key: None,
            local_msg_id: 0u16,
            remote_msg_id: 0u16,
            local_challenge: [0u8; CHALLENGE_LEN],
            remote_challenge: None,
            //challenge: None,
            //challenge_sig: None,
            authorized_keys: vec!(),
            secret_key: None,
            public_key: None,
            read_buf: [0u8; PACKET_BUF_SIZE],
            read_buf_used: 0,
            write_buf: [0u8; PACKET_BUF_SIZE],
            write_buf_used: 0,
        }
    }
}
impl OssuaryContext {
    /// Allocate a new OssuaryContext.
    ///
    /// `conn_type` is a [`ConnectionType`] indicating whether this instance
    /// is for a client or server.
    pub fn new(conn_type: ConnectionType) -> OssuaryContext {
        //let mut rng = thread_rng();
        let mut rng = OsRng::new().expect("RNG not available.");
        let sec_key = EphemeralSecret::new(&mut rng);
        let pub_key = EphemeralPublic::from(&sec_key);

        let mut challenge: [u8; CHALLENGE_LEN] = [0; CHALLENGE_LEN];
        let mut nonce: [u8; NONCE_LEN] = [0; NONCE_LEN];
        rng.fill_bytes(&mut challenge);
        rng.fill_bytes(&mut nonce);

        let key = KeyMaterial {
            secret: Some(sec_key),
            public: *pub_key.as_bytes(),
            nonce: nonce,
            session: None,
        };
        OssuaryContext {
            state: match conn_type {
                ConnectionType::Client => ConnectionState::ClientNew,
                _ => ConnectionState::ServerWaitHandshake(std::time::SystemTime::now()),
            },
            conn_type: conn_type,
            local_key: key,
            local_challenge: challenge,
            ..Default::default()
        }
    }

    /// Reset the context back to its default state.
    ///
    /// If `permanent_err` is None, this connection can be re-established by
    /// calling the connection handshake functions.  This indicates that
    /// something unexpected went wrong with the connection, such as an invalid
    /// state or corrupt data, such that reestablishing the connection may fix
    /// it.
    ///
    /// If `permanent_err` is set to some error, it indicates a permanent
    /// failure on this connection, and attempting to reestablish it will likely
    /// not work.  This includes situations where the server has rejected the
    /// connection, such as when the client's key is not authorized.
    ///
    fn reset_state(&mut self, permanent_err: Option<OssuaryError>) {
        let default = OssuaryContext::new(self.conn_type.clone());
        *self = default;
        self.state = match permanent_err {
            None => {
                match self.conn_type {
                    ConnectionType::Client => ConnectionState::ClientNew,
                    _ => ConnectionState::ServerWaitHandshake(std::time::SystemTime::now()),
                }
            },
            Some(e) => {
                ConnectionState::Failed(e)
            }
        };
    }
    /// Whether this context represents a server (as opposed to a client).
    fn is_server(&self) -> bool {
        match self.conn_type {
            ConnectionType::Client => false,
            _ => true,
        }
    }
    /// Add key received from a remote connection and generate session key
    fn add_remote_key(&mut self, public: &[u8; 32], nonce: &[u8; 12]) {
        let key = KeyMaterial {
            secret: None,
            public: public.to_owned(),
            nonce: nonce.to_owned(),
            session: None,
        };
        self.remote_key = Some(key);
        let secret = self.local_key.secret.take();
        if let Some(secret) = secret {
            self.local_key.session = Some(secret.diffie_hellman(&EphemeralPublic::from(*public)));
        }
    }
    /// Add public keys of clients permitted to connect to this server.
    ///
    /// `keys` must be an iterable of `&[u8]` slices containing valid 32-byte
    /// ed25519 public keys.  During the handshake, a client will be required
    /// to sign a challenge with its secret signing key.  The client sends the
    /// public key it signed with and the resulting signature, and the server
    /// validates that the public key is in this provided list of keys prior
    /// to validating the signature.
    ///
    /// If a client attempts to connect with a key not matching one of these
    /// provided keys, a permanent connection failure is raised on both ends.
    ///
    /// **NOTE:** keys are only checked if the context was created with
    /// [`ConnectionType::AuthenticatedServer`].
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
    /// Add authentication secret signing key
    ///
    /// ´key` must be a `&[u8]` slice containing a valid 32-byte ed25519
    /// signing key.  Signing keys should be kept secret and should be stored
    /// securely.
    ///
    /// This key is used to authenticate during the handshake if the remote
    /// server requires authentication.  During the handshake, the server will
    /// send a challenge (a buffer of random bytes) which the client signs
    /// with this secret key.  The client returns its public key and the
    /// signature of the challenge data to identify which key it is using for
    /// authentication, and to prove possession of the secret key.
    ///
    pub fn set_secret_key(&mut self, key: &[u8]) -> Result<(), OssuaryError> {
        if key.len() != 32 {
            return Err(OssuaryError::KeySize(32, key.len()));
        }
        let secret = SecretKey::from_bytes(key)?;
        let public = PublicKey::from(&secret);
        self.secret_key = Some(secret);
        self.public_key = Some(public);
        Ok(())
    }
    /// Get the client's authentication public verification key
    ///
    /// When a secret key is set with [`OssuaryContext::set_secret_key`], the
    /// matching public key is calculated.  This function returns that public
    /// key, which can be shared with a remote server for future authentication.
    ///
    pub fn public_key(&self) -> Result<&[u8], OssuaryError> {
        match self.public_key {
            None => Err(OssuaryError::InvalidKey),
            Some(ref p) => {
                Ok(p.as_bytes())
            }
        }
    }

    pub fn send_handshake<T,U>(&mut self, mut buf: T) -> Result<usize, OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Write {
        // Try to send any unsent buffered data
        match write_stored_packet(self, &mut buf) {
            Ok(w) if w == 0 => {},
            Ok(w) => return Err(OssuaryError::WouldBlock(w)),
            Err(e) => return Err(e),
        }
        let written = match self.state {
            // No-op states
            ConnectionState::ServerNew |
            ConnectionState::Encrypted => {0},

            // Timeout wait states
            ConnectionState::ServerWaitHandshake(t) |
            ConnectionState::ServerWaitAuthentication(t) |
            ConnectionState::ClientWaitHandshake(t)  => {
                let mut w: usize = 0;
                // Wait for response, with timeout
                if let Ok(dur) = t.elapsed() {
                    if dur.as_secs() > MAX_HANDSHAKE_WAIT_TIME {
                        let pkt: HandshakePacket = Default::default();
                        w = write_packet(self, &mut buf, struct_as_slice(&pkt),
                                         PacketType::Reset)?;
                        self.reset_state(None);
                    }
                }
                w
            },

            // <client> --> [session x25519 public key,
            //               session nonce,
            //               client random challenge]      --> <server>
            ConnectionState::ClientNew | // Alias of ClientSendHandshake
            ConnectionState::ClientSendHandshake => {
                // Send session public key and nonce to initiate connection
                let pkt = ClientHandshakePacket::new(&self.local_key.public,
                                                     &self.local_key.nonce,
                                                     &self.local_challenge);
                let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
                                     PacketType::ClientHandshake)?;
                self.state = ConnectionState::ClientWaitHandshake(std::time::SystemTime::now());
                w
            },

            // <client> <-- [session x25519 public key,
            //               session nonce],
            //              [[server x25519 public key,
            //                server random challenge,
            //                client challenge signature]] <-- <server>
            ConnectionState::ServerSendHandshake => {
                let server_secret = match self.secret_key {
                    Some(ref s) => match SecretKey::from_bytes(s.as_bytes()) {
                        Ok(s) => Some(s), // local copy of secret key
                        Err(_) => None,
                    },
                    _ => None,
                };
                let sig: [u8; SIGNATURE_LEN] = match server_secret {
                    Some(s) => {
                        let server_public = PublicKey::from(&s);
                        let keypair = Keypair { secret: s, public: server_public };
                        match self.remote_challenge {
                            Some(ref c) => keypair.sign(c).to_bytes(),
                            None => {
                                self.reset_state(None);
                                return Err(OssuaryError::InvalidSignature);
                            }
                        }
                    },
                    None => [0; SIGNATURE_LEN],
                };
                let server_public = match self.public_key {
                    Some(ref p) => p.as_bytes(),
                    None => &[0; KEY_LEN],
                };
                let session = match self.local_key.session {
                    Some(ref s) => s.as_bytes(),
                    None => {
                        self.reset_state(None);
                        return Err(OssuaryError::InvalidKey);
                    }
                };
                let pkt = ServerHandshakePacket::new(&self.local_key.public,
                                                     &self.local_key.nonce,
                                                     session,
                                                     server_public,
                                                     &self.local_challenge,
                                                     &sig);
                let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
                                     PacketType::ServerHandshake)?;
                self.state = ConnectionState::ServerWaitAuthentication(std::time::SystemTime::now());
                w
            },

            // <client> --> [[client x25519 public key,
            //                server challenge signature]] --> <server>
            ConnectionState::ClientSendAuthentication => {0},

            ConnectionState::Failed(ref e) => {0},
        };
        Ok(written)
    }
    pub fn recv_handshake<T,U>(&mut self, buf: T) -> Result<usize, OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Read {
        match self.state {
            ConnectionState::Encrypted => return Ok(0),
            // Timeout wait states
            ConnectionState::ServerWaitHandshake(t) |
            ConnectionState::ServerWaitAuthentication(t) |
            ConnectionState::ClientWaitHandshake(t)  => {
                let mut w: usize = 0;
                // Wait for response, with timeout
                if let Ok(dur) = t.elapsed() {
                    if dur.as_secs() > MAX_HANDSHAKE_WAIT_TIME {
                        return Err(OssuaryError::ConnectionReset);
                    }
                }
            },
            _ => {},
        }

        let (pkt, bytes_read) = match read_packet(self, buf) {
            Ok(t) => { t },
            Err(OssuaryError::WouldBlock(b)) => {
                return Err(OssuaryError::WouldBlock(b));
            }
            Err(e) => {
                self.reset_state(None);
                return Err(e);
            }
        };

        match pkt.kind() {
            PacketType::Reset => {
                self.reset_state(None);
                return Err(OssuaryError::ConnectionReset);
            },
            PacketType::Disconnect => {
                self.reset_state(Some(OssuaryError::ConnectionFailed));
                return Err(OssuaryError::ConnectionFailed);
            },
            _ => {},
        }

        if pkt.header.msg_id != self.remote_msg_id {
            println!("Message gap detected.  Restarting connection.");
            println!("Server: {}", self.is_server());
            self.reset_state(None);
            return Err(OssuaryError::InvalidPacket("Message ID does not match".into()));
        }
        self.remote_msg_id = pkt.header.msg_id + 1;

        println!("Recv packet: ({}) {:?} <- {:?}", self.is_server(), self.state, pkt.kind());
        match self.state {
            // Non-receive states.  Receiving handshake data is an error.
            ConnectionState::ClientNew |
            ConnectionState::ClientSendHandshake |
            ConnectionState::ClientSendAuthentication |
            ConnectionState::ServerSendHandshake |
            ConnectionState::Encrypted => {
                self.reset_state(None);
                return Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()));
            },

            // <client> --> [session x25519 public key,
            //               session nonce,
            //               client random challenge]      --> <server>
            ConnectionState::ServerNew |
            ConnectionState::ServerWaitHandshake(_) => {
                match pkt.kind() {
                    PacketType::ClientHandshake => {
                        if let Ok(inner_pkt) = ClientHandshakePacket::from_packet(&pkt) {
                            println!("Server got handshake? {:?}", inner_pkt.nonce);
                            let mut chal: [u8; CHALLENGE_LEN] = Default::default();
                            chal.copy_from_slice(&inner_pkt.challenge);
                            self.add_remote_key(&inner_pkt.public_key, &inner_pkt.nonce);
                            self.remote_challenge = Some(chal);
                            self.state = ConnectionState::ServerSendHandshake;
                        }
                    },
                    _ => {
                        self.reset_state(None);
                        return Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()));
                    },
                }
            },

            // <client> <-- [session x25519 public key,
            //               session nonce],
            //              [[server x25519 public key,
            //                server random challenge,
            //                client challenge signature]] <-- <server>
            ConnectionState::ClientWaitHandshake(t) => {
                println!("Client got handshake?");
            },

            // <client> --> [[client x25519 public key,
            //                server challenge signature]] --> <server>
            ConnectionState::ServerWaitAuthentication(t) => {},

            ConnectionState::Failed(ref e) => {},

        };
        Ok(bytes_read)
    }


    /// Writes the next handshake packet to the output stream.
    ///
    ///
    ///
    /// On success, returns the number of bytes written to the output buffer.
    pub fn send_handshake_old<T,U>(&mut self, mut buf: T) -> Result<usize, OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Write {
        // Try to send any unsent buffered data
        match write_stored_packet(self, &mut buf) {
            Ok(w) if w == 0 => {},
            Ok(w) => return Err(OssuaryError::WouldBlock(w)),
            Err(e) => return Err(e),
        }
        let written = match self.state {
            _ => {0},
            //ConnectionState::ServerNew => {
            //    // Wait for client to initiate connection
            //    0
            //},
            //ConnectionState::Encrypted => {
            //    // Handshake finished
            //    0
            //},
            //
            //ConnectionState::ServerWaitAck(t) |
            //ConnectionState::ServerWaitAuth(t) |
            //ConnectionState::ClientWaitKey(t) |
            //ConnectionState::ClientWaitAck(t) => {
            //    let mut w: usize = 0;
            //    // Wait for response, with timeout
            //    if let Ok(dur) = t.elapsed() {
            //        if dur.as_secs() > MAX_HANDSHAKE_WAIT_TIME {
            //            let pkt: HandshakePacket = Default::default();
            //            w = write_packet(self, &mut buf, struct_as_slice(&pkt),
            //                             PacketType::Reset)?;
            //            self.reset_state(None);
            //        }
            //    }
            //    w
            //},
            //ConnectionState::ServerSendPubKey => {
            //    // Send session public key and nonce to the client
            //    let mut pkt: HandshakePacket = Default::default();
            //    pkt.public_key.copy_from_slice(&self.local_key.public);
            //    pkt.nonce.copy_from_slice(&self.local_key.nonce);
            //    let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
            //                         PacketType::PublicKeyNonce)?;
            //    self.state = ConnectionState::ServerWaitAck(std::time::SystemTime::now());
            //    w
            //},
            //ConnectionState::ServerSendChallenge => {
            //    match self.conn_type {
            //        ConnectionType::AuthenticatedServer => {
            //            // Send a block of random data over the encrypted session to
            //            // the client.  The client must sign it with its key to prove
            //            // key possession.
            //            let mut rng = match OsRng::new() {
            //                Ok(rng) => rng,
            //                Err(_) => {
            //                    self.reset_state(None);
            //                    return Err(OssuaryError::InvalidKey);
            //                }
            //            };
            //            let aad = [];
            //            let mut challenge: [u8; CHALLENGE_LEN] = [0; CHALLENGE_LEN];
            //            rng.fill_bytes(&mut challenge);
            //            self.challenge = Some(challenge.to_vec());
            //            let mut ciphertext = Vec::with_capacity(CHALLENGE_LEN);
            //            let session_key = match self.local_key.session {
            //                Some(ref s) => s,
            //                None => {
            //                    self.reset_state(None);
            //                    return Err(OssuaryError::InvalidKey);
            //                }
            //            };
            //            let tag = match encrypt(session_key.as_bytes(),
            //                                    &self.local_key.nonce,
            //                                    &aad, &challenge, &mut ciphertext) {
            //                Ok(tag) => tag,
            //                Err(_) => {
            //                    self.reset_state(None);
            //                    return Err(OssuaryError::InvalidKey);
            //                }
            //            };
            //            let pkt: EncryptedPacket = EncryptedPacket {
            //                tag_len: tag.len() as u16,
            //                data_len: ciphertext.len() as u16,
            //            };
            //            let mut pkt_buf: Vec<u8>= vec![];
            //            pkt_buf.extend(struct_as_slice(&pkt));
            //            pkt_buf.extend(&ciphertext);
            //            pkt_buf.extend(&tag);
            //            let w = write_packet(self, &mut buf, &pkt_buf,
            //                                 PacketType::AuthChallenge)?;
            //            self.state = ConnectionState::ServerWaitAuth(std::time::SystemTime::now());
            //            w
            //        },
            //        _ => {
            //            // For unauthenticated connections, we are done.  Already encrypted.
            //            let pkt: HandshakePacket = Default::default();
            //            let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
            //                                 PacketType::PubKeyAck)?;
            //            self.state = ConnectionState::Encrypted;
            //            w // handshake is finished (success)
            //        },
            //    }
            //},
            //ConnectionState::ClientNew => {
            //    // Send session public key and nonce to initiate connection
            //    let mut pkt: HandshakePacket = Default::default();
            //    pkt.public_key.copy_from_slice(&self.local_key.public);
            //    pkt.nonce.copy_from_slice(&self.local_key.nonce);
            //    let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
            //                         PacketType::PublicKeyNonce)?;
            //    self.state = ConnectionState::ClientWaitKey(std::time::SystemTime::now());
            //    w
            //},
            //ConnectionState::ClientSendAck => {
            //    // Acknowledge reception of server's session public key and nonce
            //    let pkt: HandshakePacket = Default::default();
            //    let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
            //                         PacketType::PubKeyAck)?;
            //    self.state = ConnectionState::ClientWaitAck(std::time::SystemTime::now());
            //    w
            //},
            //ConnectionState::ClientSendAuth => {
            //    // Send signature of the server's challenge back to the server,
            //    // along with the public part of the authentication key.  This is
            //    // done over the established encrypted channel.
            //    let secret = match self.secret_key {
            //        Some(ref s) => match SecretKey::from_bytes(s.as_bytes()) {
            //            Ok(s) => s, // local copy of secret key
            //            Err(_) => {
            //                self.reset_state(Some(OssuaryError::InvalidKey));
            //                return Err(OssuaryError::InvalidKey);
            //            }
            //        },
            //        None => {
            //            self.reset_state(Some(OssuaryError::InvalidKey));
            //            return Err(OssuaryError::InvalidKey);
            //        }
            //    };
            //    let public = PublicKey::from(&secret);
            //    let keypair = Keypair { secret: secret, public: public };
            //    let sig = match self.challenge {
            //        Some(ref c) => keypair.sign(c).to_bytes(),
            //        None => {
            //            self.reset_state(None);
            //            return Err(OssuaryError::InvalidSignature);
            //        }
            //    };
            //    let mut pkt_data: Vec<u8> = Vec::with_capacity(CHALLENGE_LEN + 32);
            //    pkt_data.extend_from_slice(public.as_bytes());
            //    pkt_data.extend_from_slice(&sig);
            //    self.challenge_sig = Some(sig.to_vec());
            //
            //    let aad = [];
            //    let mut ciphertext = Vec::with_capacity(pkt_data.len());
            //    let session_key = match self.local_key.session {
            //        Some(ref s) => s,
            //        None => {
            //            self.reset_state(None);
            //            return Err(OssuaryError::InvalidKey);
            //        }
            //    };
            //    let tag = match encrypt(session_key.as_bytes(),
            //                            &self.local_key.nonce,
            //                            &aad, &pkt_data, &mut ciphertext) {
            //        Ok(t) => t,
            //        Err(_) => {
            //            self.reset_state(None);
            //            return Err(OssuaryError::InvalidKey);
            //        }
            //    };
            //
            //    let pkt: EncryptedPacket = EncryptedPacket {
            //        tag_len: tag.len() as u16,
            //        data_len: ciphertext.len() as u16,
            //    };
            //    let mut pkt_buf: Vec<u8>= vec![];
            //    pkt_buf.extend(struct_as_slice(&pkt));
            //    pkt_buf.extend(&ciphertext);
            //    pkt_buf.extend(&tag);
            //    let w = write_packet(self, &mut buf, &pkt_buf,
            //                         PacketType::AuthResponse)?;
            //    self.state = ConnectionState::Encrypted;
            //    w // handshake is finished (success)
            //},
            //ConnectionState::Failed(_) => {
            //    // This is a permanent failure.
            //    let pkt: HandshakePacket = Default::default();
            //    let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
            //                         PacketType::Disconnect)?;
            //    self.reset_state(Some(OssuaryError::ConnectionFailed));
            //    w // handshake is finished (failed)
            //},
        };
        Ok(written)
    }

    /// Receive the next handshake packet from the input buffer
    ///
    /// On success, returns the number of bytes consumed from the input buffer.
    pub fn recv_handshake_old<T,U>(&mut self, buf: T) -> Result<usize, OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Read {
        let mut bytes_read: usize = 0;

        match self.state {
            ConnectionState::Encrypted => return Ok(0),
            _ => {},
        }

        let pkt: NetworkPacket = match read_packet(self, buf) {
            Ok((p, r)) => {
                bytes_read += r;
                p
            },
            Err(OssuaryError::WouldBlock(b)) => {
                return Err(OssuaryError::WouldBlock(b));
            }
            Err(e) => {
                self.reset_state(None);
                return Err(e);
            }
        };

        let mut error = false;
        match pkt.kind() {
            PacketType::Reset => {
                self.reset_state(None);
                return Err(OssuaryError::ConnectionReset);
            },
            PacketType::Disconnect => {
                self.reset_state(Some(OssuaryError::ConnectionFailed));
                return Err(OssuaryError::ConnectionFailed);
            },
            _ => {},
        }

        if pkt.header.msg_id != self.remote_msg_id {
            println!("Message gap detected.  Restarting connection.");
            println!("Server: {}", self.is_server());
            self.reset_state(None);
            return Err(OssuaryError::InvalidPacket("Message ID does not match".into()));
        }
        self.remote_msg_id = pkt.header.msg_id + 1;

        match self.state {
            _ => {error = true;},
            //ConnectionState::ServerNew => {
            //    match pkt.kind() {
            //        PacketType::PublicKeyNonce => {
            //            let data_pkt: Result<&HandshakePacket, _> = interpret_packet(&pkt);
            //            match data_pkt {
            //                Ok(ref data_pkt) => {
            //                    self.add_remote_key(&data_pkt.public_key, &data_pkt.nonce);
            //                    self.state = ConnectionState::ServerSendPubKey;
            //                },
            //                Err(_) => {
            //                    error = true;
            //                },
            //            }
            //        },
            //        _ => { error = true; }
            //    }
            //},
            //ConnectionState::ServerWaitAck(_t) => {
            //    match pkt.kind() {
            //        PacketType::PubKeyAck => {
            //            self.state = ConnectionState::ServerSendChallenge;
            //        },
            //        _ => { error = true; }
            //    }
            //},
            //ConnectionState::ServerWaitAuth(_t) => {
            //    match pkt.kind() {
            //        PacketType::AuthResponse => {
            //            match interpret_packet_extra::<EncryptedPacket>(&pkt) {
            //                Ok((data_pkt, rest)) => {
            //                    let ciphertext = &rest[..data_pkt.data_len as usize];
            //                    let tag = &rest[data_pkt.data_len as usize..];
            //                    let aad = [];
            //                    let mut plaintext = Vec::with_capacity(ciphertext.len());
            //                    let session_key = match self.local_key.session {
            //                        Some(ref k) => k,
            //                        None => {
            //                            self.reset_state(None);
            //                            return Err(OssuaryError::InvalidKey);
            //                        }
            //                    };
            //                    let remote_nonce = match self.remote_key {
            //                        Some(ref rem) => rem.nonce,
            //                        None => {
            //                            self.reset_state(None);
            //                            return Err(OssuaryError::InvalidKey);
            //                        }
            //                    };
            //                    decrypt(session_key.as_bytes(),
            //                            &remote_nonce,
            //                            &aad, &ciphertext, &tag, &mut plaintext)?;
            //                    let pubkey = &plaintext[0..32];
            //                    let sig = &plaintext[32..];
            //                    if self.authorized_keys.iter().filter(
            //                        |k| &pubkey == k).count() > 0 {
            //                        let public = match PublicKey::from_bytes(pubkey) {
            //                            Ok(p) => p,
            //                            Err(_) => {
            //                                self.reset_state(None);
            //                                return Err(OssuaryError::InvalidKey);
            //                            }
            //                        };
            //                        let sig = match Signature::from_bytes(sig) {
            //                            Ok(s) => s,
            //                            Err(_) => {
            //                                self.reset_state(None);
            //                                return Err(OssuaryError::InvalidKey);
            //                            }
            //                        };
            //                        let challenge = match self.challenge {
            //                            Some(ref c) => c,
            //                            None => {
            //                                self.reset_state(None);
            //                                return Err(OssuaryError::InvalidKey);
            //                            }
            //                        };
            //                        match public.verify(challenge, &sig) {
            //                            Ok(_) => {
            //                                self.state = ConnectionState::Encrypted;
            //                            },
            //                            Err(_) => {
            //                                println!("Verify bad");
            //                                self.state = ConnectionState::Failed(
            //                                    OssuaryError::InvalidSignature);
            //                            },
            //                        }
            //                    }
            //                    else {
            //                        println!("Key not allowed");
            //                        self.state = ConnectionState::Failed(OssuaryError::InvalidKey);
            //                    }
            //                },
            //                Err(_) => {
            //                    self.reset_state(None);
            //                    return Err(OssuaryError::InvalidPacket("Response invalid".into()));
            //                },
            //            };
            //        },
            //        _ => { error = true; }
            //    }
            //},
            //ConnectionState::ClientWaitKey(_t) => {
            //    match pkt.kind() {
            //        PacketType::PublicKeyNonce => {
            //            let data_pkt: Result<&HandshakePacket, _> = interpret_packet(&pkt);
            //            match data_pkt {
            //                Ok(data_pkt) => {
            //                    self.add_remote_key(&data_pkt.public_key, &data_pkt.nonce);
            //                    self.state = ConnectionState::ClientSendAck;
            //                },
            //                Err(_) => {
            //                    error = true;
            //                },
            //            }
            //        },
            //        _ => {
            //            error = true;
            //        }
            //    }
            //},
            //ConnectionState::ClientWaitAck(_t) => {
            //    match pkt.kind() {
            //        PacketType::PubKeyAck => {
            //            self.state = ConnectionState::Encrypted;
            //        },
            //        PacketType::AuthChallenge => {
            //            match interpret_packet_extra::<EncryptedPacket>(&pkt) {
            //                Ok((data_pkt, rest)) => {
            //                    let ciphertext = &rest[..data_pkt.data_len as usize];
            //                    let tag = &rest[data_pkt.data_len as usize..];
            //                    let aad = [];
            //                    let mut plaintext = Vec::with_capacity(ciphertext.len());
            //
            //                    let session_key = match self.local_key.session {
            //                        Some(ref k) => k,
            //                        None => {
            //                            self.reset_state(None);
            //                            return Err(OssuaryError::InvalidKey);
            //                        }
            //                    };
            //                    let remote_nonce = match self.remote_key {
            //                        Some(ref rem) => rem.nonce,
            //                        None => {
            //                            self.reset_state(None);
            //                            return Err(OssuaryError::InvalidKey);
            //                        }
            //                    };
            //                    decrypt(session_key.as_bytes(),
            //                            &remote_nonce,
            //                            &aad, &ciphertext, &tag, &mut plaintext)?;
            //                    self.challenge = Some(plaintext);
            //                    self.state = ConnectionState::ClientSendAuth;
            //                },
            //                Err(_) => {
            //                    error = true;
            //                },
            //            }
            //        },
            //        _ => {
            //            error = true;
            //        },
            //    }
            //},
            //ConnectionState::ServerSendPubKey |
            //ConnectionState::ServerSendChallenge |
            //ConnectionState::ClientNew |
            //ConnectionState::ClientSendAck |
            //ConnectionState::ClientSendAuth |
            //ConnectionState::Encrypted => {
            //    // no-op
            //},
            //ConnectionState::Failed(_) => {
            //    error = true;
            //},
        }
        if error {
            self.reset_state(None);
            return Err(OssuaryError::ConnectionReset);
        }
        Ok(bytes_read)
    }

    /// Returns whether the handshake process is complete.
    ///
    ///
    pub fn handshake_done(&self) -> Result<bool, &OssuaryError> {
        match self.state {
            ConnectionState::Encrypted => Ok(true),
            ConnectionState::Failed(ref e) => Err(e),
            _ => Ok(false),
        }
    }

    pub fn send_data<T,U>(&mut self,
                          in_buf: &[u8],
                          mut out_buf: T) -> Result<usize, OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Write {
        // Try to send any unsent buffered data
        match write_stored_packet(self, &mut out_buf) {
            Ok(w) if w == 0 => {},
            Ok(w) => return Err(OssuaryError::WouldBlock(w)),
            Err(e) => return Err(e),
        }
        match self.state {
            ConnectionState::Encrypted => {},
            _ => {
                return Err(OssuaryError::InvalidPacket(
                    "Encrypted channel not established.".into()));
            }
        }
        let aad = [];
        let mut ciphertext = Vec::with_capacity(in_buf.len());
        let session_key = match self.local_key.session {
            Some(ref k) => k,
            None => {
                self.reset_state(None);
                return Err(OssuaryError::InvalidKey);;
            }
        };
        let tag = match encrypt(session_key.as_bytes(),
                                &self.local_key.nonce, &aad, in_buf, &mut ciphertext) {
            Ok(t) => t,
            Err(_) => {
                self.reset_state(None);
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
        let written = write_packet(self, &mut out_buf, &buf,
                                   PacketType::EncryptedData)?;
        Ok(written)
    }

    pub fn recv_data<T,U,R,V>(&mut self,
                              in_buf: T,
                              mut out_buf: R) -> Result<(usize, usize), OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Read,
          R: std::ops::DerefMut<Target = V>,
          V: std::io::Write {
        let bytes_written: usize;
        let mut bytes_read: usize = 0;
        match self.state {
            ConnectionState::Encrypted => {},
            _ => {
                return Err(OssuaryError::InvalidPacket(
                    "Encrypted channel not established.".into()));
            }
        }

        match read_packet(self, in_buf) {
            Ok((pkt, bytes)) => {
                bytes_read += bytes;
                if pkt.header.msg_id != self.remote_msg_id {
                    let msg_id = pkt.header.msg_id;
                    println!("Message gap detected.  Restarting connection. ({} != {})",
                             msg_id, self.remote_msg_id);
                    println!("Server: {}", self.is_server());
                    self.reset_state(None);
                    return Err(OssuaryError::InvalidPacket("Message ID mismatch".into()))
                }
                self.remote_msg_id = pkt.header.msg_id + 1;

                match pkt.kind() {
                    PacketType::EncryptedData => {
                        match interpret_packet_extra::<EncryptedPacket>(&pkt) {
                            Ok((data_pkt, rest)) => {
                                let ciphertext = &rest[..data_pkt.data_len as usize];
                                let tag = &rest[data_pkt.data_len as usize..];
                                let aad = [];
                                let mut plaintext = Vec::with_capacity(ciphertext.len());
                                let session_key = match self.local_key.session {
                                    Some(ref k) => k,
                                    None => {
                                        self.reset_state(None);
                                        return Err(OssuaryError::InvalidKey);
                                    }
                                };
                                let remote_nonce = match self.remote_key {
                                    Some(ref rem) => rem.nonce,
                                    None => {
                                        self.reset_state(None);
                                        return Err(OssuaryError::InvalidKey);
                                    }
                                };
                                decrypt(session_key.as_bytes(),
                                        &remote_nonce,
                                        &aad, &ciphertext, &tag, &mut plaintext)?;
                                bytes_written = match out_buf.write(&plaintext) {
                                    Ok(w) => w,
                                    Err(e) => return Err(e.into()),
                                };
                            },
                            Err(_) => {
                                self.reset_state(None);
                                return Err(OssuaryError::InvalidKey);
                            },
                        }
                    },
                    _ => {
                        return Err(OssuaryError::InvalidPacket(
                            "Received non-encrypted data on encrypted channel.".into()));
                    },
                }
            },
            Err(OssuaryError::WouldBlock(b)) => {
                return Err(OssuaryError::WouldBlock(b));
            },
            Err(_e) => {
                self.reset_state(None);
                return Err(OssuaryError::InvalidPacket("Packet header did not parse.".into()));
            },
        }
        Ok((bytes_read, bytes_written))
    }

    pub fn flush<R,V>(&mut self,
                      mut out_buf: R) -> Result<usize, OssuaryError>
    where R: std::ops::DerefMut<Target = V>,
          V: std::io::Write {
        return write_stored_packet(self, &mut out_buf);
    }
}

/// Cast the data bytes in a NetworkPacket into a struct
fn interpret_packet<'a, T>(pkt: &'a NetworkPacket) -> Result<&'a T, OssuaryError> {
    let s: &T = slice_as_struct(&pkt.data)?;
    Ok(s)
}

/// Cast the data bytes in a NetworkPacket into a struct, and also return the
/// remaining unused bytes if the data is larger than the struct.
fn interpret_packet_extra<'a, T>(pkt: &'a NetworkPacket)
                                 -> Result<(&'a T, &'a [u8]), OssuaryError> {
    let s: &T = slice_as_struct(&pkt.data)?;
    Ok((s, &pkt.data[::std::mem::size_of::<T>()..]))
}

/// Read a complete network packet from the input stream.
///
/// On success, returns a NetworkPacket struct containing the header and data,
/// and a `usize` indicating how many bytes were consumed from the input buffer.
fn read_packet<T,U>(conn: &mut OssuaryContext,
                    mut stream: T) ->Result<(NetworkPacket, usize), OssuaryError>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Read {
    let header_size = ::std::mem::size_of::<PacketHeader>();
    let bytes_read: usize;
    match stream.read(&mut conn.read_buf[conn.read_buf_used..]) {
        Ok(b) => bytes_read = b,
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            return Err(OssuaryError::WouldBlock(0))
        },
        Err(e) => return Err(e.into()),
    }
    conn.read_buf_used += bytes_read;
    let buf: &[u8] = &conn.read_buf;
    let hdr = PacketHeader {
        len: u16::from_be_bytes(buf[0..2].try_into()?),
        msg_id: u16::from_be_bytes(buf[2..4].try_into()?),
        packet_type: PacketType::from_u16(u16::from_be_bytes(buf[4..6].try_into()?)),
        _reserved: u16::from_be_bytes(buf[6..8].try_into()?),
    };
    let packet_len = hdr.len as usize;
    if conn.read_buf_used < header_size + packet_len {
        if header_size + packet_len > PACKET_BUF_SIZE {
            panic!("oversized packet");
        }
        return Err(OssuaryError::WouldBlock(bytes_read));
    }
    let buf: Box<[u8]> = (&conn.read_buf[header_size..header_size+packet_len])
        .to_vec().into_boxed_slice();
    let excess = conn.read_buf_used - header_size - packet_len;
    unsafe {
        // no safe way to memmove() in Rust?
        std::ptr::copy::<u8>(
            conn.read_buf.as_ptr().offset((header_size + packet_len) as isize),
            conn.read_buf.as_mut_ptr(),
            excess);
    }
    conn.read_buf_used = excess;
    Ok((NetworkPacket {
        header: hdr,
        data: buf,
    },
    header_size + packet_len))
}

/// Write a packet from OssuaryContext's internal storage to the out buffer.
///
/// All packets are buffered to internal storage before writing, so this is
/// the function responsible for putting all packets "on the wire".
///
/// On success, returns the number of bytes written to the output buffer
fn write_stored_packet<T,U>(conn: &mut OssuaryContext,
                            stream: &mut T) -> Result<usize, OssuaryError>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Write {
    let mut written = 0;
    while written < conn.write_buf_used {
        match stream.write(&conn.write_buf[written..conn.write_buf_used]) {
            Ok(w) => {
                written += w;
            },
            Err(e) => {
                if written > 0 && written < conn.write_buf_used {
                    unsafe {
                        // no safe way to memmove() in Rust?
                        std::ptr::copy::<u8>(
                            conn.write_buf.as_ptr().offset(written as isize),
                            conn.write_buf.as_mut_ptr(),
                            conn.write_buf_used - written);
                    }
                }
                conn.write_buf_used -= written;
                return Err(e.into());
            },
        }
    }
    conn.write_buf_used = 0;
    Ok(written)
}

/// Write a packet to the OssuaryContext's internal packet buffer
///
/// All packets are buffered internally because there is no guarantee that a
/// complete packet can be written without blocking, and Ossuary is a non-
/// blocking library.
///
/// On success, returns the number of bytes written to the output buffer.
fn write_packet<T,U>(conn: &mut OssuaryContext,
                     stream: &mut T, data: &[u8],
                     kind: PacketType) -> Result<usize, OssuaryError>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Write {
    let msg_id = conn.local_msg_id as u16;
    conn.write_buf[0..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
    conn.write_buf[2..4].copy_from_slice(&msg_id.to_be_bytes());
    conn.write_buf[4..6].copy_from_slice(&(kind as u16).to_be_bytes());
    conn.write_buf[6..8].copy_from_slice(&(0u16).to_be_bytes());
    conn.write_buf[8..8+data.len()].copy_from_slice(&data);
    conn.write_buf_used = 8 + data.len();
    conn.local_msg_id += 1;
    let written = write_stored_packet(conn, stream)?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_set_authorized_keys() {
        let mut conn = OssuaryContext::new(ConnectionType::AuthenticatedServer);

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

}
