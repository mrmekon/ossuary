use crate::*;

use comm::{read_packet, write_packet, write_stored_packet};

const SERVER_HANDSHAKE_SUBPACKET_LEN: usize = ::std::mem::size_of::<ServerEncryptedHandshakePacket>() +
    ::std::mem::size_of::<EncryptedPacket>() + TAG_LEN;
const CLIENT_AUTH_SUBPACKET_LEN: usize = ::std::mem::size_of::<ClientEncryptedAuthenticationPacket>() +
    ::std::mem::size_of::<EncryptedPacket>() + TAG_LEN;

#[repr(C,packed)]
struct ResetPacket {
    len: u16,
    _reserved: u16,
}
impl Default for ResetPacket {
    fn default() -> ResetPacket {
        ResetPacket {
            len: ::std::mem::size_of::<ResetPacket> as u16,
            _reserved: 0u16,
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
impl ServerEncryptedHandshakePacket {
    fn from_bytes(data: &[u8]) -> Result<&ServerEncryptedHandshakePacket, OssuaryError> {
        let s: &ServerEncryptedHandshakePacket = slice_as_struct(&data)?;
        Ok(s)
    }
}

#[repr(C,packed)]
struct ServerHandshakePacket {
    len: u16,
    version: u8,
    _reserved: [u8; 5],
    public_key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    subpacket: [u8; SERVER_HANDSHAKE_SUBPACKET_LEN],
}
impl Default for ServerHandshakePacket {
    fn default() -> ServerHandshakePacket {
        ServerHandshakePacket {
            len: (NONCE_LEN + KEY_LEN + SERVER_HANDSHAKE_SUBPACKET_LEN + 8) as u16,
            version: PROTOCOL_VERSION,
            _reserved: [0u8; 5],
            public_key: [0u8; KEY_LEN],
            nonce: [0u8; NONCE_LEN],
            subpacket: [0; SERVER_HANDSHAKE_SUBPACKET_LEN],
        }
    }
}
impl ServerHandshakePacket {
    fn new(session_pubkey: &[u8], nonce: &[u8], session_privkey: &[u8],
           server_pubkey: &[u8], challenge: &[u8], signature: &[u8]) -> Result<ServerHandshakePacket, OssuaryError> {
        let mut pkt: ServerHandshakePacket = Default::default();
        let mut enc_pkt: ServerEncryptedHandshakePacket = Default::default();
        pkt.public_key.copy_from_slice(session_pubkey);
        pkt.nonce.copy_from_slice(nonce);
        enc_pkt.public_key.copy_from_slice(server_pubkey);
        enc_pkt.challenge.copy_from_slice(challenge);
        enc_pkt.signature.copy_from_slice(signature);
        let mut subpkt: &mut [u8] = &mut pkt.subpacket;
        encrypt_to_bytes(session_privkey, nonce, struct_as_slice(&enc_pkt), &mut subpkt)?;
        Ok(pkt)
    }
    fn from_packet(pkt: &NetworkPacket) -> Result<&ServerHandshakePacket, OssuaryError> {
        let hs_pkt = interpret_packet::<ServerHandshakePacket>(&pkt);
        // TODO: validate len/version fields
        hs_pkt
    }
}

#[repr(C,packed)]
struct ClientEncryptedAuthenticationPacket {
    public_key: [u8; KEY_LEN],
    signature: [u8; SIGNATURE_LEN],
}
impl Default for ClientEncryptedAuthenticationPacket {
    fn default() -> ClientEncryptedAuthenticationPacket {
        ClientEncryptedAuthenticationPacket {
            public_key: [0u8; KEY_LEN],
            signature: [0u8; SIGNATURE_LEN],
        }
    }
}
impl ClientEncryptedAuthenticationPacket {
    fn from_bytes(data: &[u8]) -> Result<&ClientEncryptedAuthenticationPacket, OssuaryError> {
        let s: &ClientEncryptedAuthenticationPacket = slice_as_struct(&data)?;
        Ok(s)
    }
}

#[repr(C,packed)]
struct ClientAuthenticationPacket {
    len: u16,
    version: u8,
    _reserved: [u8; 5],
    subpacket: [u8; CLIENT_AUTH_SUBPACKET_LEN],
}
impl Default for ClientAuthenticationPacket {
    fn default() -> ClientAuthenticationPacket {
        ClientAuthenticationPacket {
            len: (CLIENT_AUTH_SUBPACKET_LEN + 8) as u16,
            version: PROTOCOL_VERSION,
            _reserved: [0u8; 5],
            subpacket: [0u8; CLIENT_AUTH_SUBPACKET_LEN],
        }
    }
}
impl ClientAuthenticationPacket {
    fn new(nonce: &[u8], session_privkey: &[u8],
           client_pubkey: &[u8], signature: &[u8]) -> Result<ClientAuthenticationPacket, OssuaryError> {
        let mut pkt: ClientAuthenticationPacket = Default::default();
        let mut enc_pkt: ClientEncryptedAuthenticationPacket = Default::default();
        enc_pkt.public_key.copy_from_slice(client_pubkey);
        enc_pkt.signature.copy_from_slice(signature);
        let mut subpkt: &mut [u8] = &mut pkt.subpacket;
        encrypt_to_bytes(session_privkey, nonce, struct_as_slice(&enc_pkt), &mut subpkt)?;
        Ok(pkt)
    }
    fn from_packet(pkt: &NetworkPacket) -> Result<&ClientAuthenticationPacket, OssuaryError> {
        let hs_pkt = interpret_packet::<ClientAuthenticationPacket>(&pkt);
        // TODO: validate len/version fields
        hs_pkt
    }
}

impl OssuaryConnection {
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
            ConnectionState::Encrypted => {0},

            // Timeout wait states
            ConnectionState::ServerWaitHandshake(t) |
            ConnectionState::ServerWaitAuthentication(t) |
            ConnectionState::ClientWaitHandshake(t)  => {
                let mut w: usize = 0;
                // Wait for response, with timeout
                if let Ok(dur) = t.elapsed() {
                    if dur.as_secs() > MAX_HANDSHAKE_WAIT_TIME {
                        let pkt: ResetPacket = Default::default();
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
            ConnectionState::ClientSendHandshake => {
                // Send session public key and nonce to initiate connection
                let chal = self.local_auth.challenge.unwrap_or([0u8; CHALLENGE_LEN]);
                let pkt = ClientHandshakePacket::new(&self.local_key.public,
                                                     &self.local_key.nonce,
                                                     &chal);
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
                // Get a local copy of server's secret auth key, if it has one.
                // Default to 0s.
                let server_secret = match self.local_auth.secret_key {
                    Some(ref s) => match SecretKey::from_bytes(s.as_bytes()) {
                        Ok(s) => Some(s),
                        Err(_) => None,
                    },
                    _ => None,
                };
                // Sign the client's challenge if we have a key,
                // default to 0s.
                let sig: [u8; SIGNATURE_LEN] = match server_secret {
                    Some(s) => {
                        let server_public = PublicKey::from(&s);
                        let keypair = Keypair { secret: s, public: server_public };
                        match self.remote_auth.challenge {
                            Some(ref c) => keypair.sign(c).to_bytes(),
                            None => {
                                self.reset_state(None);
                                return Err(OssuaryError::InvalidSignature);
                            }
                        }
                    },
                    None => [0; SIGNATURE_LEN],
                };
                // Get server's public auth key, if it has one.
                // Default to 0s.
                let server_public = match self.local_auth.public_key {
                    Some(ref p) => p.as_bytes(),
                    None => &[0; KEY_LEN],
                };
                // Get session encryption key, which must be known by now.
                let session = match self.local_key.session {
                    Some(ref s) => s.as_bytes(),
                    None => {
                        self.reset_state(None);
                        return Err(OssuaryError::InvalidKey);
                    }
                };
                let chal = self.local_auth.challenge.unwrap_or([0u8; CHALLENGE_LEN]);
                let pkt = ServerHandshakePacket::new(&self.local_key.public,
                                                     &self.local_key.nonce,
                                                     session,
                                                     server_public,
                                                     &chal,
                                                     &sig)?;
                let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
                                     PacketType::ServerHandshake)?;
                self.state = ConnectionState::ServerWaitAuthentication(std::time::SystemTime::now());
                w
            },

            // <client> --> [[client x25519 public key,
            //                server challenge signature]] --> <server>
            ConnectionState::ClientSendAuthentication => {
                // Get a local copy of client's secret auth key, if it has one.
                // Default to 0s.
                let client_secret = match self.local_auth.secret_key {
                    Some(ref s) => match SecretKey::from_bytes(s.as_bytes()) {
                        Ok(s) => Some(s),
                        Err(_) => None,
                    },
                    _ => None,
                };
                // Sign the client's challenge if we have a key,
                // default to 0s.
                let sig: [u8; SIGNATURE_LEN] = match client_secret {
                    Some(s) => {
                        let client_public = PublicKey::from(&s);
                        let keypair = Keypair { secret: s, public: client_public };
                        match self.remote_auth.challenge {
                            Some(ref c) => keypair.sign(c).to_bytes(),
                            None => {
                                self.reset_state(None);
                                return Err(OssuaryError::InvalidSignature);
                            }
                        }
                    },
                    None => [0; SIGNATURE_LEN],
                };
                // Get server's public auth key, if it has one.
                // Default to 0s.
                let client_public = match self.local_auth.public_key {
                    Some(ref p) => p.as_bytes(),
                    None => &[0; KEY_LEN],
                };
                // Get session encryption key, which must be known by now.
                let session = match self.local_key.session {
                    Some(ref s) => s.as_bytes(),
                    None => {
                        self.reset_state(None);
                        return Err(OssuaryError::InvalidKey);
                    }
                };
                let pkt = ClientAuthenticationPacket::new(&self.local_key.nonce,
                                                          session,
                                                          client_public,
                                                          &sig)?;
                let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
                                     PacketType::ClientAuthentication)?;
                self.state = ConnectionState::Encrypted;
                w
            },

            ConnectionState::Failed(ref _e) => {
                // TODO: fail
                unimplemented!();
            },
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
            ConnectionState::ServerWaitHandshake(_) => {
                match pkt.kind() {
                    PacketType::ClientHandshake => {
                        if let Ok(inner_pkt) = ClientHandshakePacket::from_packet(&pkt) {
                            let mut chal: [u8; CHALLENGE_LEN] = Default::default();
                            chal.copy_from_slice(&inner_pkt.challenge);
                            self.add_remote_key(&inner_pkt.public_key, &inner_pkt.nonce);
                            self.remote_auth = AuthKeyMaterial {
                                challenge: Some(chal),
                                public_key: None,
                                signature: None,
                                secret_key: None,
                            };
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
            ConnectionState::ClientWaitHandshake(_t) => {
                match pkt.kind() {
                    PacketType::ServerHandshake => {
                        // TODO: handle error, reset state
                        if let Ok(inner_pkt) = ServerHandshakePacket::from_packet(&pkt) {
                            self.add_remote_key(&inner_pkt.public_key, &inner_pkt.nonce);
                            let mut plaintext: [u8; SERVER_HANDSHAKE_SUBPACKET_LEN] = [0u8; SERVER_HANDSHAKE_SUBPACKET_LEN];
                            let session = match self.local_key.session {
                                Some(ref s) => s.as_bytes(),
                                _ => {
                                    self.reset_state(None);
                                    return Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()));
                                }
                            };
                            let nonce = match self.remote_key {
                                Some(ref k) => k.nonce,
                                _ => {
                                    self.reset_state(None);
                                    return Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()));
                                }
                            };
                            let mut pt: &mut [u8] = &mut plaintext;
                            // note: pt is consumed by decrypt_to_bytes
                            let _ = decrypt_to_bytes(session, &nonce, &inner_pkt.subpacket, &mut pt)?;
                            if let Ok(enc_pkt) = ServerEncryptedHandshakePacket::from_bytes(&plaintext) {
                                let mut chal: [u8; CHALLENGE_LEN] = [0u8; CHALLENGE_LEN];
                                let mut sig: [u8; SIGNATURE_LEN] = [0u8; SIGNATURE_LEN];
                                chal.copy_from_slice(&enc_pkt.challenge);
                                sig.copy_from_slice(&enc_pkt.signature);
                                let pubkey = match PublicKey::from_bytes(&enc_pkt.public_key) {
                                    Ok(p) => p,
                                    _ => {
                                        self.reset_state(None);
                                        return Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()));
                                    }
                                };
                                let signature = match Signature::from_bytes(&sig) {
                                    Ok(s) => s,
                                    Err(_) => {
                                        self.reset_state(None);
                                        return Err(OssuaryError::InvalidSignature);
                                    }
                                };
                                // TODO: support trust on first use
                                if self.authorized_keys.len() > 0 {
                                    if chal.iter().all(|x| *x == 0) ||
                                        sig.iter().all(|x| *x == 0) ||
                                        enc_pkt.public_key.iter().all(|x| *x == 0) {
                                            // Parameters must be non-zero
                                            self.reset_state(None);
                                            return Err(OssuaryError::InvalidSignature);
                                        }
                                    match pubkey.verify(&chal, &signature) {
                                        Ok(_) => {},
                                        Err(_) => {
                                            self.reset_state(None);
                                            return Err(OssuaryError::InvalidSignature);
                                        },
                                    }
                                }
                                self.remote_auth = AuthKeyMaterial {
                                    challenge: Some(chal),
                                    public_key: Some(pubkey),
                                    signature: Some(sig),
                                    secret_key: None,
                                };
                                self.state = ConnectionState::ClientSendAuthentication;
                            }
                        }
                    },
                    _ => {
                        self.reset_state(None);
                        return Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()));
                    },
                }
            },

            // <client> --> [[client x25519 public key,
            //                server challenge signature]] --> <server>
            ConnectionState::ServerWaitAuthentication(_t) => {
                match pkt.kind() {
                    PacketType::ClientAuthentication => {
                        // TODO: handle error, reset state
                        if let Ok(inner_pkt) = ClientAuthenticationPacket::from_packet(&pkt) {
                            let mut plaintext: [u8; CLIENT_AUTH_SUBPACKET_LEN] = [0u8; CLIENT_AUTH_SUBPACKET_LEN];
                            let session = match self.local_key.session {
                                Some(ref s) => s.as_bytes(),
                                _ => {
                                    self.reset_state(None);
                                    return Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()));
                                }
                            };
                            let nonce = match self.remote_key {
                                Some(ref k) => k.nonce,
                                _ => {
                                    self.reset_state(None);
                                    return Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()));
                                }
                            };
                            let mut pt: &mut [u8] = &mut plaintext;
                            // note: pt is consumed by decrypt_to_bytes
                            let _ = decrypt_to_bytes(session, &nonce, &inner_pkt.subpacket, &mut pt)?;
                            if let Ok(enc_pkt) = ClientEncryptedAuthenticationPacket::from_bytes(&plaintext) {
                                let mut sig: [u8; SIGNATURE_LEN] = [0u8; SIGNATURE_LEN];
                                sig.copy_from_slice(&enc_pkt.signature);
                                let pubkey = match PublicKey::from_bytes(&enc_pkt.public_key) {
                                    Ok(p) => p,
                                    _ => {
                                        self.reset_state(None);
                                        return Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()));
                                    }
                                };
                                let challenge = self.local_auth.challenge.unwrap_or([0u8; CHALLENGE_LEN]);
                                let signature = match Signature::from_bytes(&sig) {
                                    Ok(s) => s,
                                    Err(_) => {
                                        self.reset_state(None);
                                        return Err(OssuaryError::InvalidSignature);
                                    }
                                };
                                match self.conn_type {
                                    // TODO: only permit known pubkeys
                                    ConnectionType::AuthenticatedServer => {
                                        if challenge.iter().all(|x| *x == 0) ||
                                            sig.iter().all(|x| *x == 0) ||
                                            enc_pkt.public_key.iter().all(|x| *x == 0) {
                                                // Parameters must be non-zero
                                                self.reset_state(None);
                                                return Err(OssuaryError::InvalidSignature);
                                        }
                                        match pubkey.verify(&challenge, &signature) {
                                            Ok(_) => {},
                                            Err(_) => {
                                                self.reset_state(None);
                                                return Err(OssuaryError::InvalidSignature);
                                            },
                                        }
                                    }
                                    _ => {},
                                }
                                self.remote_auth.signature = Some(sig);
                                self.remote_auth.public_key = Some(pubkey);
                                self.state = ConnectionState::Encrypted;
                            }
                        }
                    },
                    _ => {
                        self.reset_state(None);
                        return Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()));
                    },
                }
            },

            ConnectionState::Failed(ref _e) => {
                // TODO: fail
                unimplemented!();
            },

        };
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

fn decrypt_to_bytes<T,U>(session_key: &[u8], nonce: &[u8],
                         data: &[u8], mut out: T) -> Result<usize, OssuaryError>
where T: std::ops::DerefMut<Target = U>,
      U: std::io::Write {
    let s: &EncryptedPacket = slice_as_struct(data)?;
    if s.tag_len != 16 {
        return Err(OssuaryError::InvalidPacket("Invalid packet length".into()));
    }
    let data_pkt = s;
    let rest = &data[::std::mem::size_of::<EncryptedPacket>()..];
    let ciphertext = &rest[..data_pkt.data_len as usize];
    let tag = &rest[data_pkt.data_len as usize..];
    let aad = [];
    decrypt(session_key,
            &nonce,
            &aad, &ciphertext, &tag,
            out.deref_mut())?;
    Ok(ciphertext.len())
}