// Copyright 2019 Trevor Bentley
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
use crate::*;

use rand::RngCore;
use rand::rngs::OsRng;

impl OssuaryConnection {
    fn generate_session_material() -> Result<SessionKeyMaterial, OssuaryError> {
        let mut rng = OsRng::new().expect("RNG not available.");
        let sec_key = EphemeralSecret::new(&mut rng);
        let pub_key = EphemeralPublic::from(&sec_key);
        let mut nonce: [u8; NONCE_LEN] = [0; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        Ok(SessionKeyMaterial {
            secret: Some(sec_key),
            public: *pub_key.as_bytes(),
            nonce: nonce,
            session: None,
        })
    }

    /// Allocate a new OssuaryConnection.
    ///
    /// `conn_type` is a [`ConnectionType`] indicating whether this instance
    /// is for a client or server.
    ///
    /// `auth_secret_key` is the secret portion of the long-term Ed25519 key
    /// used for host authentication.  If `None` is provided, a keypair will
    /// be generated for the lifetime of this connection object.  This key
    /// can be changed with [`OssuaryConnection::set_secret_key`].
    ///
    pub fn new(conn_type: ConnectionType, auth_secret_key: Option<&[u8]>) -> Result<OssuaryConnection, OssuaryError> {
        let mut rng = OsRng::new().expect("RNG not available.");

        let mut challenge: [u8; CHALLENGE_LEN] = [0; CHALLENGE_LEN];
        rng.fill_bytes(&mut challenge);

        let key = OssuaryConnection::generate_session_material()?;

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

    /// Terminate a connection, or an on-going connection attempt.
    ///
    /// Calling this immediately closes the local end of Ossuary's connection,
    /// and queues a disconnect packet to be sent to the remote host to inform
    /// it to close its end.
    ///
    /// After calling disconnect(), the application should continue calling
    /// Ossuary's functions (or at least its handshake functions) in a loop
    /// until [`OssuaryConnection::handshake_done`] returns the matching error.
    /// This allows Ossuary to generate the final disconnect packet.
    ///
    /// The handshake will return [`OssuaryError::ConnectionFailed`] if 'error'
    /// is true, or [`OssuaryError::ConnectionClosed`] otherwise.
    ///
    /// 'error' - Indicates the reason for termination.  True means the channel
    ///           is being closed because of some error, False means it is being
    ///           closed due to completion or a clean shutdown.
    ///
    pub fn disconnect(&mut self, error: bool) {
        match error {
            true => self.reset_state(Some(OssuaryError::ConnectionFailed)),
            false => self.reset_state(Some(OssuaryError::ConnectionClosed)),
        }
    }

    /// Get the initial state machine state of this connection
    pub(crate) fn initial_state(&self) -> ConnectionState {
        match self.conn_type {
            ConnectionType::Client => ConnectionState::ClientSendHandshake,
            _ => ConnectionState::ServerWaitHandshake(std::time::SystemTime::now()),
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
    pub(crate) fn reset_state(&mut self, permanent_err: Option<OssuaryError>) {
        self.local_key = OssuaryConnection::generate_session_material().unwrap_or_default();
        self.remote_key = None;
        self.local_msg_id = 0;
        self.remote_msg_id = 0;
        self.remote_auth = Default::default();
        self.read_buf = [0u8; PACKET_BUF_SIZE];
        self.read_buf_used = 0;
        self.write_buf = [0u8; PACKET_BUF_SIZE];
        self.write_buf_used = 0;
        self.reset_count += 1;
        let perm_error = match self.reset_count {
            c if c < MAX_RESET_COUNT => permanent_err,
            _ => Some(OssuaryError::ConnectionFailed),
        };
        self.state = match perm_error {
            None => ConnectionState::Resetting(true),
            Some(e) => ConnectionState::Failing(e),
        };
    }
    /// Whether this context represents a server (as opposed to a client).
    pub fn is_server(&self) -> bool {
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
    /// Set authentication secret signing key
    ///
    /// Changes the secret authentication key of this side of the connection,
    /// which was previously set by [`OssuaryConnection::new`]
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
