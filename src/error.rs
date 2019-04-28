use crate::*;

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
    /// secret or public key in [`OssuaryConnection::set_authorized_keys`] or
    /// [`OssuaryConnection::set_secret_key`].  Both should be 32 bytes.
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