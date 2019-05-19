use crate::*;

//use rand::thread_rng;
use rand::RngCore;
use rand::rngs::OsRng;

impl OssuaryConnection {
    /// Allocate a new OssuaryConnection.
    ///
    /// `conn_type` is a [`ConnectionType`] indicating whether this instance
    /// is for a client or server.
    ///
    /// `auth_secret_key` is the secret portion of the long-term Ed25519 key
    /// used for host authentication.  If `None` is provided, a keypair will
    /// be generated for the lifetime of this connection object.
    pub fn new(conn_type: ConnectionType, auth_secret_key: Option<&[u8]>) -> Result<OssuaryConnection, OssuaryError> {
        //let mut rng = thread_rng();
        let mut rng = OsRng::new().expect("RNG not available.");
        let sec_key = EphemeralSecret::new(&mut rng);
        let pub_key = EphemeralPublic::from(&sec_key);

        let mut challenge: [u8; CHALLENGE_LEN] = [0; CHALLENGE_LEN];
        let mut nonce: [u8; NONCE_LEN] = [0; NONCE_LEN];
        rng.fill_bytes(&mut challenge);
        rng.fill_bytes(&mut nonce);

        let key = SessionKeyMaterial {
            secret: Some(sec_key),
            public: *pub_key.as_bytes(),
            nonce: nonce,
            session: None,
        };
        let (auth_sec, auth_pub) = match auth_secret_key {
            Some(s) => {
                // Use the given secret key
                if s.len() != 32 {
                    return Err(OssuaryError::KeySize(32, s.len()));
                }
                let secret = SecretKey::from_bytes(s)?;
                let public = PublicKey::from(&secret);
                (Some(secret), Some(public))
            }
            None => {
                match conn_type {
                    // Allow no auth key for clients
                    ConnectionType::Client => (None, None),
                    // Generate a random auth key for servers, if not provided
                    _ => {
                        let mut sec: [u8; KEY_LEN] = [0u8; KEY_LEN];
                        rng.fill_bytes(&mut sec);
                        let secret = SecretKey::from_bytes(&sec)?;
                        let public = PublicKey::from(&secret);
                        (Some(secret), Some(public))
                    }
                }
            },
        };
        let auth = AuthKeyMaterial {
            challenge: Some(challenge),
            signature: None,
            secret_key: auth_sec,
            public_key: auth_pub,
        };
        Ok(OssuaryConnection {
            state: match conn_type {
                ConnectionType::Client => ConnectionState::ClientSendHandshake,
                _ => ConnectionState::ServerWaitHandshake(std::time::SystemTime::now()),
            },
            conn_type: conn_type,
            local_key: key,
            local_auth: auth,
            ..Default::default()
        })
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
    pub(crate) fn reset_state(&mut self, permanent_err: Option<OssuaryError>) {
        self.local_key = Default::default();
        self.remote_key = None;
        self.local_msg_id = 0;
        self.remote_msg_id = 0;
        self.remote_auth = Default::default();
        self.read_buf = [0u8; PACKET_BUF_SIZE];
        self.read_buf_used = 0;
        self.write_buf = [0u8; PACKET_BUF_SIZE];
        self.write_buf_used = 0;
        self.state = match permanent_err {
            None => {
                match self.conn_type {
                    ConnectionType::Client => ConnectionState::ClientSendHandshake,
                    _ => ConnectionState::ServerWaitHandshake(std::time::SystemTime::now()),
                }
            },
            Some(e) => {
                ConnectionState::Failed(e)
            }
        };
    }
    /// Whether this context represents a server (as opposed to a client).
    pub(crate) fn is_server(&self) -> bool {
        match self.conn_type {
            ConnectionType::Client => false,
            _ => true,
        }
    }
    /// Add key received from a remote connection and generate session key
    pub(crate) fn add_remote_key(&mut self, public: &[u8; 32], nonce: &[u8; 12]) {
        let key = SessionKeyMaterial {
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

    /// Add public key of permitted remote hosts
    ///
    /// During the handshake, both hosts will be required to sign a challenge
    /// with their secret authentication key.  The host sends both the signature
    /// and the public key it signed with.  The other side validates the
    /// signature, and verifies that the public key is in the list of authorized
    /// keys.
    ///
    /// Unauthenticated servers do not verify the public key.  Authenticated
    /// servers do verify the public key, and reject the connection if the key
    /// is unknown.  Clients verify the public key, and raise
    /// [`OssuaryError::UntrustedServer`] if the key is unknown, permitting a
    /// Trust-On-First-Use scheme if desired.
    ///
    /// If a key is rejected, permanent connection failures are raised on both sides.
    ///
    pub fn add_authorized_key(&mut self, key: &[u8]) -> Result<(), OssuaryError> {
        if key.len() != 32 {
            return Err(OssuaryError::KeySize(32, key.len()));
        }
        let mut key_owned = [0u8; 32];
        key_owned.copy_from_slice(key);
        self.authorized_keys.push(key_owned);

        // If handshake is waiting for key approval, check if this is the key.
        match self.state {
            ConnectionState::ClientWaitServerApproval => {
                match self.remote_auth.public_key {
                    Some(remote_key) => {
                        if remote_key.as_bytes() == key {
                            self.state = ConnectionState::ClientSendAuthentication
                        }
                    },
                    _ => {},
                }
            },
            _ => {},
        };
        Ok(())
    }

    /// Add public keys of permitted remote hosts
    ///
    /// `keys` must be an iterable of `&[u8]` slices containing valid 32-byte
    /// ed25519 public keys.
    ///
    /// See [`OssuaryConnection::add_authorized_key`] for documentation.
    ///
    pub fn add_authorized_keys<'a,T>(&mut self, keys: T) -> Result<usize, OssuaryError>
    where T: std::iter::IntoIterator<Item = &'a [u8]> {
        let mut count: usize = 0;
        for key in keys {
            let _ = self.add_authorized_key(key)?;
            count += 1;
        }
        Ok(count)
    }
    /// Add authentication secret signing key
    ///
    /// `key` must be a `&[u8]` slice containing a valid 32-byte ed25519
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
        self.local_auth.secret_key = Some(secret);
        self.local_auth.public_key = Some(public);
        Ok(())
    }
    /// Get the local host's authentication public key
    ///
    /// When a secret key is set with [`OssuaryConnection::set_secret_key`], the
    /// matching public key is calculated.  This function returns that public
    /// key, which can be shared with a remote server for future authentication.
    pub fn local_public_key(&self) -> Result<&[u8], OssuaryError> {
        match self.local_auth.public_key {
            None => Err(OssuaryError::InvalidKey),
            Some(ref p) => Ok(p.as_bytes()),
        }
    }
    /// Get the remote host's authentication public key
    ///
    /// When a connection is established, or during the initial handshake after
    /// reeiving an [`OssuaryError::UntrustedServer`] response, this returns the
    /// remote side's authentication public key.  This is typically needed by a
    /// client to get the remote server's key for a Trust-On-First-Use scheme.
    pub fn remote_public_key(&self) -> Result<&[u8], OssuaryError> {
        match self.remote_auth.public_key {
            None => Err(OssuaryError::InvalidKey),
            Some(ref p) => Ok(p.as_bytes()),
        }
    }
}
