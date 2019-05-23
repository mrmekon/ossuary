//! # Ossuary
//!
//! Ossuary is a library for establishing an encrypted and authenticated
//! communication channel between a client and a server.
//!
//! It establishes a 1-to-1 client/server communication channel that requires
//! reliable, in-order packet delivery, such as provided by TCP sockets.
//!
//! Authentication and verification of remote hosts is optional, and requires
//! an out-of-band exchange of host public keys, or a Trust-On-First-Use policy.
//!
//! ## Ciphers:
//!
//! * Ephemeral session keys: Curve25519 ECDH.
//! * Session encryption: ChaCha20 symmetrical cipher.
//! * Message authentication: Poly1305 MAC.
//! * Host authentication: Ed25519 signature scheme.
//!
//! ## The handshake protocol:
//!
//! A 3-packet (1.5 roundtrip) handshake is always performed.
//!
//! The necessary fields to perform an ECDH key exchange and establish a
//! shared session key are sent in the clear, while fields for host verification
//! are encrypted with the established session key.
//!
//! In the following diagram, fields in [single brackets] are sent in the clear,
//! and those in [[double brackets]] are encrypted with the shared session key:
//!
//! ```text
//! <client> --> [  session x25519 public key,
//!                 session nonce,
//!                 client random challenge                ] --> <server>
//! <client> <-- [  session x25519 public key,
//!                 session nonce],
//!              [[ auth ed25519 public key,
//!                 server random challenge,
//!                 signature(pubkey, nonce, challenge),  ]] <-- <server>
//! <client> --> [[ auth ed25519 public key,
//!                 signature(pubkey, nonce, challenge),  ]] --> <server>
//! ```
//!
//! Host authentication (verifying the identity of the remote server or client)
//! is optional.   In non-authenticated flows, "auth public key", "challenge",
//! and "signature" fields are set to all 0s, but are still transmitted.
//!
//! ### Fields
//!
//! * **session public key**: Public part of randomly generated public/private
//!   key pair for this session, used to generate an ephemeral session key.
//! * **challenge**: Randomly generated string for remote party to sign to prove
//!   its identity in authenticated connections.
//! * **auth public key**: Public part of long-lived public/private key pair
//!   used for host authentication.
//! * **signature**: Signature, with long-lived private authentication key, of
//!   local party's session public key and nonce (the ECDH parameters) and
//!   remote party's random challenge, to prove host identity and prevent
//!   man-in-the-middle attacks.
//!
//! ## Security Protections
//!
//! ### Passive Snooping
//!
//! Per-packet encryption with ChaCha20 prevents passive monitoring of the
//! contents of the communication channel.
//!
//! ### Malleability
//!
//! Poly1305 MAC prevents active manipulation of packets in-flight, ensuring
//! that any manipulation will cause the channel to terminate.
//!
//! ### Replay Attacks
//!
//! Poly1305 MAC combined with a nonce scheme prevents replay attacks, and
//! prevents manipulation of message order.
//!
//! ### Forward Secrecy
//!
//! Per-session encryption with ephemeral x25519 keys ensures that the
//! compromise of one session does not necessarily result in the compromise of
//! any previous or future session.
//!
//! ### Man-in-the-Middle
//!
//! Host authentication with Ed25519 signature verification of ECDH parameters
//! prevents man-in-the-middle attacks.  Host authentication is optional, and
//! requires out-of-band exchange of host public keys or a Trust On First Use
//! policy, so MITM attacks may be possible if care is not taken.
//!
//! ## Security Limitations
//!
//! ### Code Quality
//!
//! This software is not code reviewed, and no security analysis has been
//! performed.
//!
//! ### Keys In RAM
//!
//! No efforts are taken to secure key data in RAM.  Attacks from privileged
//! local processes are possible.
//!
//! ### Keys On Disk
//!
//! No mechanisms are provided for storing keys on disk.  Secure key storage
//! is left as a task for the caller.
//!
//! ### Side-Channel
//!
//! No efforts are taken to protect against side channel attacks such as timing
//! or cache analysis.
//!
//! ### Software Dependencies
//!
//! This software depends on third-party software libraries for all core
//! cryptographic algorithms, which have not been code reviewed and are subject
//! to change.
//!
//! ### Trust-On-First-Use (TOFU)
//!
//! Host authentication supports a trust-on-first-use policy, which opens the
//! possibility of man-in-the-middle attacks if the first connection is
//! compromised.
//!

//
// TODO
//  - rustdoc everything
//

pub mod clib;
mod connection;
mod handshake;
mod comm;
mod error;

pub use error::OssuaryError;

extern crate x25519_dalek;
extern crate ed25519_dalek;
extern crate rand;
extern crate chacha20_poly1305_aead;

use chacha20_poly1305_aead::{encrypt,decrypt};
use x25519_dalek::{EphemeralSecret, PublicKey as EphemeralPublic, SharedSecret};
use ed25519_dalek::{Signature, Keypair, SecretKey, PublicKey};

use rand::rngs::OsRng;

const PROTOCOL_VERSION: u8 = 1u8;

// Maximum time to wait (in seconds) for a handshake response
const MAX_HANDSHAKE_WAIT_TIME: u64 = 3u64;

// Maximum number of times a connection can reset before a permanent failure.
const MAX_RESET_COUNT: usize = 5;

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

/// The packet types used by the Ossuary protocol.
#[repr(u16)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum PacketType {
    /// Should never be encountered.
    Unknown = 0x00,

    /// Handshake packet from client to server
    ///
    /// Contains:
    ///  - session public key (client)
    ///  - session nonce (client)
    ///  - session challenge (client)
    ClientHandshake = 0x01,

    /// Handshake packet from server to client
    ///
    /// Contains:
    ///  - session public key (server)
    ///  - session nonce (server)
    ///  - session challenge (server, encrypted)
    ///  - authentication public key (server, encrypted)
    ///  - signature of client challenge (encrypted)
    ServerHandshake = 0x02,

    /// Authentication packet from client to server
    ///
    /// Contains:
    ///  - authentication public key (client, encrypted)
    ///  - signature of server challenge (encrypted)
    ClientAuthentication = 0x03,

    /// Tell other side of connection to disconnect permanently.
    Disconnect = 0x10,

    /// Tell other side to reset connection, but re-handshaking is allowed.
    Reset = 0x11,

    /// Encrypted data packet
    EncryptedData = 0x20,
}
impl PacketType {
    /// Convert u16 integer to a PacketType enum
    pub fn from_u16(i: u16) -> PacketType {
        match i {
            0x01 => PacketType::ClientHandshake,
            0x02 => PacketType::ServerHandshake,
            0x03 => PacketType::ClientAuthentication,
            0x10 => PacketType::Disconnect,
            0x11 => PacketType::Reset,
            0x20 => PacketType::EncryptedData,
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

/// Internal state of OssuaryConnection state machine.
#[derive(Debug)]
enum ConnectionState {
    /// Server is waiting for handshake packet from a client
    ///
    /// Matching client state: ClientSendHandshake
    /// Next server state: ServerSendHandshake
    ServerWaitHandshake(std::time::SystemTime),

    /// Server about to send handshake packet to client
    ///
    /// Matching client state: ClientWaitHandshake
    /// Next server state: ServerWaitAuthentication
    ServerSendHandshake,

    /// Server is waiting for authentication packet from client
    ///
    /// Matching client state: ClientSendAuthentication
    /// Next server state: Encrypted
    ServerWaitAuthentication(std::time::SystemTime),

    /// Client is about to send handshake packet to server
    ///
    /// Matching server state: ServerWaitHandshake
    /// Next client state: ClientWaitHandshake
    ClientSendHandshake,

    /// Client is waiting for handshake packet from server
    ///
    /// Matching server state: ServerSendHandshake
    /// Next client state: ClientSendAuthentication
    ClientWaitHandshake(std::time::SystemTime),

    /// Client is about to send authentication packet to server
    ///
    /// Matching server state: ServerWaitAuthentication
    /// Next client state: Encrypted
    ClientSendAuthentication,

    /// Client is about to raise an UntrustedServer error to the caller
    ///
    /// The client has established and verified a connection with a remote
    /// server, but the server's authentication key is unknown.  The
    /// [`OssuaryError::UntrustedServer`] will be raised on the next call to
    /// [`OssuaryConnection::handhake_done`].
    ClientRaiseUntrustedServer,

    /// Client is waiting for the caller to approve an unknown remote server
    ///
    /// After raising [`OssuaryError::UntrustedServer`], the client waits in
    /// this state until the server's public key is added to the list of
    /// authorized keys with [`OssuaryConnection::add_authorized_key`], or
    /// the connection is killed.  This permits callers to implement a
    /// Trust-On-First-Use policy.
    ClientWaitServerApproval,

    /// Connection is established, encrypted, and optionally authenticated.
    Encrypted,

    /// Connection has temporarily failed and will be reset
    ///
    /// An error occurred that might be recoverable.  A reset packet will be
    /// sent to the remote host to inform it to reset as well.
    ///
    /// Parameter is true if this side is initiating the reset, false if this
    /// side is responding to a received reset.
    Resetting(bool),

    /// Waiting for other side of connection to confirm reset
    ///
    /// The local host has sent a reset packet to the remote host, and is
    /// waiting for the remote host to confirm that it has reset its state.
    /// This is a temporary holding state to ensure that all packets that
    /// were on the wire at the time of the error are received before a
    /// new connection attempt is made.
    ResetWait,

    /// Connection has failed permanently because of the associated error
    ///
    /// The connection is known to have failed on the local side, but the
    /// failure has not yet been communicated to the remote host.
    Failing(OssuaryError),

    /// Connection has failed permanently
    ///
    /// Both hosts are informed of the failure, and the connection will not be
    /// recovered.
    Failed(OssuaryError),
}

#[derive(Default)]
struct AuthKeyMaterial {
    secret_key: Option<SecretKey>,
    public_key: Option<PublicKey>,
    challenge: Option<[u8; CHALLENGE_LEN]>,
    signature: Option<[u8; SIGNATURE_LEN]>,
}

#[derive(Default)]
struct SessionKeyMaterial {
    secret: Option<EphemeralSecret>,
    public: [u8; 32],
    session: Option<SharedSecret>,
    nonce: [u8; 12],
}

/// Enum specifying the client or server role of a [`OssuaryConnection`]
#[derive(Clone)]
pub enum ConnectionType {
    /// This context is a client
    Client,

    /// This context is a server that requires authentication.
    ///
    /// Authenticated servers only allow connections from clients with secret
    /// keys set using [`OssuaryConnection::set_secret_key`], and with the
    /// matching public key registered with the server using
    /// [`OssuaryConnection::add_authorized_keys`].
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
/// OssuaryConnection instance.  It holds all of the state required to maintain
/// one side of an encrypted connection.
///
/// A context is created with [`OssuaryConnection::new`], passing it a
/// [`ConnectionType`] identifying whether it is to act as a client or server.
/// Server contexts can optionally require authentication, verified by providing
/// a list of public keys of permitted clients with
/// [`OssuaryConnection::add_authorized_keys`].  Clients, on the other hand,
/// authenticate by setting their secret key with
/// [`OssuaryConnection::set_secret_key`].
///
/// A server must create one OssuaryConnection per connected client.  Multiple
/// connections cannot be multiplexed in one context.
///
/// A OssuaryConnection keeps temporary buffers for both received and soon-to-be
/// transmitted data.  This means they are not particularly small objects, but
/// in exchange they can read and write from/to streams set in non-blocking mode
/// without blocking single-threaded applications.
///
pub struct OssuaryConnection {
    state: ConnectionState,
    conn_type: ConnectionType,
    local_key: SessionKeyMaterial, // session key
    remote_key: Option<SessionKeyMaterial>, // session key
    local_msg_id: u16,
    remote_msg_id: u16,
    authorized_keys: Vec<[u8; 32]>,
     //a TODO: secret key should be stored in a single spot on the heap and
    // cleared after use.  Perhaps use clear_on_drop crate.
    local_auth: AuthKeyMaterial,
    remote_auth: AuthKeyMaterial,
    read_buf: [u8; PACKET_BUF_SIZE],
    read_buf_used: usize,
    write_buf: [u8; PACKET_BUF_SIZE],
    write_buf_used: usize,
    reset_count: usize,
}
impl Default for OssuaryConnection {
    fn default() -> Self {
        OssuaryConnection {
            state: ConnectionState::ClientSendHandshake,
            conn_type: ConnectionType::Client,
            local_key: Default::default(),
            remote_key: None,
            local_msg_id: 0u16,
            remote_msg_id: 0u16,
            authorized_keys: vec!(),
            local_auth: Default::default(),
            remote_auth: Default::default(),
            read_buf: [0u8; PACKET_BUF_SIZE],
            read_buf_used: 0,
            write_buf: [0u8; PACKET_BUF_SIZE],
            write_buf_used: 0,
            reset_count: 0,
        }
    }
}

/// Generate secret/public Ed25519 keypair for host authentication
pub fn generate_auth_keypair() -> Result<([u8; KEY_LEN],[u8; KEY_LEN]), OssuaryError> {
    let mut rng = OsRng::new()?;
    let keypair: Keypair = Keypair::generate(&mut rng);
    Ok((keypair.secret.to_bytes(), keypair.public.to_bytes()))
}

/// Cast the data bytes in a NetworkPacket into a struct
fn interpret_packet<'a, T>(pkt: &'a NetworkPacket) -> Result<&'a T, OssuaryError> {
    let s: &T = slice_as_struct(&pkt.data)?;
    Ok(s)
}

fn increment_nonce(nonce: &mut [u8]) -> bool {
    let wrapped = nonce.iter_mut().rev().fold(1, |acc, x| {
        let (val,carry) = x.overflowing_add(acc);
        *x = val;
        carry as u8
    });
    wrapped != 0
}

/// Cast the data bytes in a NetworkPacket into a struct, and also return the
/// remaining unused bytes if the data is larger than the struct.
fn interpret_packet_extra<'a, T>(pkt: &'a NetworkPacket)
                                 -> Result<(&'a T, &'a [u8]), OssuaryError> {
    let s: &T = slice_as_struct(&pkt.data)?;
    Ok((s, &pkt.data[::std::mem::size_of::<T>()..]))
}

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

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_add_authorized_keys() {
        let mut conn = OssuaryConnection::new(ConnectionType::AuthenticatedServer, None).unwrap();

        // Vec of slices
        let keys: Vec<&[u8]> = vec![
            &[0xbe, 0x1c, 0xa0, 0x74, 0xf4, 0xa5, 0x8b, 0xbb,
              0xd2, 0x62, 0xa7, 0xf9, 0x52, 0x3b, 0x6f, 0xb0,
              0xbb, 0x9e, 0x86, 0x62, 0x28, 0x7c, 0x33, 0x89,
              0xa2, 0xe1, 0x63, 0xdc, 0x55, 0xde, 0x28, 0x1f]
        ];
        let _ = conn.add_authorized_keys(keys).unwrap();

        // Vec of owned arrays
        let keys: Vec<[u8; 32]> = vec![
            [0xbe, 0x1c, 0xa0, 0x74, 0xf4, 0xa5, 0x8b, 0xbb,
             0xd2, 0x62, 0xa7, 0xf9, 0x52, 0x3b, 0x6f, 0xb0,
             0xbb, 0x9e, 0x86, 0x62, 0x28, 0x7c, 0x33, 0x89,
             0xa2, 0xe1, 0x63, 0xdc, 0x55, 0xde, 0x28, 0x1f]
        ];
        let _ = conn.add_authorized_keys(keys.iter().map(|x| x.as_ref()).collect::<Vec<&[u8]>>()).unwrap();

        // Vec of vecs
        let keys: Vec<Vec<u8>> = vec![
            vec![0xbe, 0x1c, 0xa0, 0x74, 0xf4, 0xa5, 0x8b, 0xbb,
                 0xd2, 0x62, 0xa7, 0xf9, 0x52, 0x3b, 0x6f, 0xb0,
                 0xbb, 0x9e, 0x86, 0x62, 0x28, 0x7c, 0x33, 0x89,
                 0xa2, 0xe1, 0x63, 0xdc, 0x55, 0xde, 0x28, 0x1f]
        ];
        let _ = conn.add_authorized_keys(keys.iter().map(|x| x.as_slice())).unwrap();
    }
}
