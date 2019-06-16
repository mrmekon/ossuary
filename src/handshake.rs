//
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

use comm::{read_packet, write_packet, write_stored_packet};

use std::io::Write;

const CLIENT_HANDSHAKE_PACKET_LEN: usize = CHALLENGE_LEN + NONCE_LEN + KEY_LEN + 8;
const CLIENT_AUTH_PACKET_LEN: usize = CLIENT_AUTH_SUBPACKET_LEN + 8;
const SERVER_HANDSHAKE_PACKET_LEN: usize = NONCE_LEN + KEY_LEN + SERVER_HANDSHAKE_SUBPACKET_LEN + 8;
const SERVER_HANDSHAKE_SUBPACKET_LEN: usize = ::std::mem::size_of::<ServerEncryptedHandshakePacket>() +
    ::std::mem::size_of::<EncryptedPacket>() + TAG_LEN;
const CLIENT_AUTH_SUBPACKET_LEN: usize = ::std::mem::size_of::<ClientEncryptedAuthenticationPacket>() +
    ::std::mem::size_of::<EncryptedPacket>() + TAG_LEN;

#[repr(C,packed)]
pub(crate) struct ResetPacket {
    len: u16,
    pub(crate) error: bool,
    _reserved: u8,
}
impl Default for ResetPacket {
    fn default() -> ResetPacket {
        ResetPacket {
            len: ::std::mem::size_of::<ResetPacket> as u16,
            error: true,
            _reserved: 0u8,
        }
    }
}
impl ResetPacket {
    fn closed() -> ResetPacket {
        ResetPacket {
            len: ::std::mem::size_of::<ResetPacket> as u16,
            error: false,
            _reserved: 0u8,
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
            len: CLIENT_HANDSHAKE_PACKET_LEN as u16,
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
        match hs_pkt {
            Ok(pkt) => {
                if pkt.version != PROTOCOL_VERSION {
                    return Err(OssuaryError::WrongProtocolVersion(pkt.version, PROTOCOL_VERSION));
                }
                if pkt.len as usize != CLIENT_HANDSHAKE_PACKET_LEN {
                    return Err(OssuaryError::InvalidPacket("Unexpected packet size.".into()));
                }
            },
            _ => {},
        }
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
            len: SERVER_HANDSHAKE_PACKET_LEN as u16,
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
        encrypt_to_bytes(session_privkey, nonce, struct_as_slice(&enc_pkt), &mut pkt.subpacket)?;
        Ok(pkt)
    }
    fn from_packet(pkt: &NetworkPacket) -> Result<&ServerHandshakePacket, OssuaryError> {
        let hs_pkt = interpret_packet::<ServerHandshakePacket>(&pkt);
        match hs_pkt {
            Ok(pkt) => {
                if pkt.version != PROTOCOL_VERSION {
                    return Err(OssuaryError::WrongProtocolVersion(pkt.version, PROTOCOL_VERSION));
                }
                if pkt.len as usize != SERVER_HANDSHAKE_PACKET_LEN {
                    return Err(OssuaryError::InvalidPacket("Unexpected packet size.".into()));
                }
            },
            _ => {},
        }
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
            len: CLIENT_AUTH_PACKET_LEN as u16,
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
        encrypt_to_bytes(session_privkey, nonce, struct_as_slice(&enc_pkt), &mut pkt.subpacket)?;
        Ok(pkt)
    }
    fn from_packet(pkt: &NetworkPacket) -> Result<&ClientAuthenticationPacket, OssuaryError> {
        let hs_pkt = interpret_packet::<ClientAuthenticationPacket>(&pkt);
        match hs_pkt {
            Ok(pkt) => {
                if pkt.version != PROTOCOL_VERSION {
                    return Err(OssuaryError::WrongProtocolVersion(pkt.version, PROTOCOL_VERSION));
                }
                if pkt.len as usize != CLIENT_AUTH_PACKET_LEN {
                    return Err(OssuaryError::InvalidPacket("Unexpected packet size.".into()));
                }
            },
            _ => {},
        }
        hs_pkt
    }
}

impl OssuaryConnection {
    /// Returns whether the handshake process is complete.
    ///
    /// Returns an error if the connection has failed, and specifically raises
    /// [`OssuaryError::UntrustedServer`] if the handshake has stalled because
    /// the remote host sent an authentication key that is not trusted.
    ///
    /// In the event of an untrusted server, calling
    /// [`OssuaryConnection::add_authorized_key`] will mark the key as trusted
    /// and allow the handshake to continue.  This should only be done if the
    /// application is implementing a Trust-On-First-Use policy, and has
    /// verified that the remote host's key has never been seen before.  It is
    /// always best practice to prompt the user in this case before continuing.
    ///
    pub fn handshake_done(&mut self) -> Result<bool, OssuaryError> {
        match self.state {
            ConnectionState::Encrypted => Ok(true),
            ConnectionState::Failed(ref e) => Err(e.clone()),
            ConnectionState::ClientRaiseUntrustedServer => {
                self.state = ConnectionState::ClientWaitServerApproval;
                let mut key: Vec<u8> = Vec::new();
                match self.remote_auth.public_key {
                    Some(ref p) => key.extend_from_slice(p.as_bytes()),
                    None => key.extend_from_slice(&[0; KEY_LEN]),
                };
                Err(OssuaryError::UntrustedServer(key))
            },
            _ => Ok(false),
        }
    }

    /// Write the next handshake packet into the given buffer
    ///
    /// If a handshake packet is ready to be sent, this function writes the
    /// encrypted packet into the provided buffer.
    ///
    /// This is a critical part of the handshaking stage, when a connection to
    /// a remote host is securely established.  Each side of the connection must
    /// call send_handshake() continuously, and any data that is written to the
    /// data buffer must be sent to the remote host.  This should be done until
    /// [`OssuaryConnection::handshake_done()`] returns true.
    ///
    /// Note that Ossuary does not perform network operations itself.  It is the
    /// caller's responsibility to put the written data on the wire.  However,
    /// you may pass a 'buf' that does this automatically, such as a TcpStream.
    ///
    /// Returns the number of bytes written into `buf`, or an error.  You must
    /// handle [`OssuaryError::WouldBlock`], which is a recoverable error, but
    /// indicates that some bytes were written to the buffer.
    pub fn send_handshake<T,U>(&mut self, mut buf: T) -> Result<usize, OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Write {
        // Try to send any unsent buffered data
        match write_stored_packet(self, &mut buf) {
            Ok(w) if w == 0 => {},
            Ok(w) => return Err(OssuaryError::WouldBlock(w)),
            Err(e) => return Err(e),
        }

        let result: Result<(usize, ConnectionState), OssuaryError> = match self.state {
            // No-op states
            ConnectionState::Failed(_) |
            ConnectionState::ResetWait |
            ConnectionState::Encrypted |
            ConnectionState::ClientRaiseUntrustedServer |
            ConnectionState::ClientWaitServerApproval => {
                return Ok(0);
            },
            // Timeout wait states
            ConnectionState::ServerWaitHandshake(t) |
            ConnectionState::ServerWaitAuthentication(t) |
            ConnectionState::ClientWaitHandshake(t)  => {
                // Wait for response, with timeout
                self.check_timeout(t);
                Ok((0, self.state.clone()))
            },
            // Handshake transmission states
            ConnectionState::ClientSendHandshake => { self.send_client_handshake(buf) },
            ConnectionState::ServerSendHandshake => { self.send_server_handshake(buf) },
            ConnectionState::ClientSendAuthentication => { self.send_client_authentication(buf) },
            // Error states
            ConnectionState::Failing(ref e) => {
                let e = e.clone(); // cure borrow-checker woes
                self.send_disconnect(e, buf)
            },
            ConnectionState::Resetting(initial) => { self.send_reset(initial, buf) }
        };

        match result {
            Ok((written, state)) => {
                self.state = state;
                Ok(written)
            }
            Err(e) => {
                self.reset_state(None);
                Err(e)
            },
        }
    }

    /// Ready to send a reset packet
    fn send_reset<T,U>(&mut self, initial: bool, mut buf: T) -> Result<(usize, ConnectionState), OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Write {
        // Tell remote host to reset
        let pkt: ResetPacket = Default::default();
        let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
                             PacketType::Reset)?;
        self.local_msg_id = 0;
        let state = match initial {
            true => ConnectionState::ResetWait,
            false => self.initial_state(),
        };
        Ok((w, state))
    }

    /// Ready to send a disconnect packet
    fn send_disconnect<T,U>(&mut self, e: OssuaryError,
                            mut buf: T) -> Result<(usize, ConnectionState), OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Write {
        // Tell remote host to disconnect
        let pkt: ResetPacket = match e {
            OssuaryError::ConnectionClosed => ResetPacket::closed(),
            _ => Default::default(),
        };
        let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
                             PacketType::Disconnect)?;
        Ok((w, ConnectionState::Failed(e)))
    }

    /// Ready to send a client handshake packet
    fn send_client_handshake<T,U>(&mut self, mut buf: T) -> Result<(usize, ConnectionState), OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Write {
        // Send session public key and nonce to initiate connection
        let chal = self.local_auth.challenge.unwrap_or([0u8; CHALLENGE_LEN]);
        let pkt = ClientHandshakePacket::new(&self.local_key.public,
                                             &self.local_key.nonce,
                                             &chal);
        let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
                             PacketType::ClientHandshake)?;
        let state = ConnectionState::ClientWaitHandshake(std::time::SystemTime::now());
        Ok((w, state))
    }

    /// Ready to send a server handshake packet
    fn send_server_handshake<T,U>(&mut self, mut buf: T) -> Result<(usize, ConnectionState), OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Write {
        let sig = self.sign_remote_challenge();
        // Get session encryption key, which must be known by now.
        let server_public = self.local_auth.public_key.unwrap_or_default();
        let session = self.local_key.session.as_ref().map(|s| s.as_bytes()).unwrap_or(&[0u8; KEY_LEN]);
        let chal = self.local_auth.challenge.unwrap_or([0u8; CHALLENGE_LEN]);
        let pkt = ServerHandshakePacket::new(&self.local_key.public,
                                             &self.local_key.nonce,
                                             session,
                                             server_public.as_bytes(),
                                             &chal,
                                             &sig)?;
        let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
                             PacketType::ServerHandshake)?;
        increment_nonce(&mut self.local_key.nonce);
        let state = ConnectionState::ServerWaitAuthentication(std::time::SystemTime::now());
        Ok((w, state))
    }

    /// Ready to send a client authentication packet
    fn send_client_authentication<T,U>(&mut self, mut buf: T) -> Result<(usize, ConnectionState), OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Write {
        let sig = self.sign_remote_challenge();
        // Get session encryption key, which must be known by now.
        let server_public = self.local_auth.public_key.unwrap_or_default();
        let session = self.local_key.session.as_ref().map(|s| s.as_bytes()).unwrap_or(&[0u8; KEY_LEN]);
        let pkt = ClientAuthenticationPacket::new(&self.local_key.nonce,
                                                  session,
                                                  server_public.as_bytes(),
                                                  &sig)?;
        let w = write_packet(self, &mut buf, struct_as_slice(&pkt),
                             PacketType::ClientAuthentication)?;
        increment_nonce(&mut self.local_key.nonce);
        let state = ConnectionState::Encrypted;
        Ok((w, state))
    }

    /// Read the next handshake packet from the given buffer
    ///
    /// If a handshake packet has been received, this function reads and parses
    /// the encrypted packet from the provided buffer and updates its internal
    /// connection state.
    ///
    /// This is a critical part of the handshaking stage, when a connection to
    /// a remote host is securely established.  Each side of the connection must
    /// call recv_handshake() whenever data is received from the network until
    /// [`OssuaryConnection::handshake_done()`] returns true.
    ///
    /// Returns the number of bytes read from `buf`, or an error.  It is the
    /// caller's responsibility to ensure that the consumed bytes are removed
    /// from the data buffer before it is used again.  You must handle
    /// [`OssuaryError::WouldBlock`], which is a recoverable error, but
    /// indicates that some bytes were also read from the buffer.
    pub fn recv_handshake<T,U>(&mut self, buf: T) -> Result<usize, OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Read {
        match self.state {
            ConnectionState::Failed(_) |
            ConnectionState::Encrypted => return Ok(0),
            // Timeout wait states
            ConnectionState::ServerWaitHandshake(t) |
            ConnectionState::ServerWaitAuthentication(t) |
            ConnectionState::ClientWaitHandshake(t)  => {
                // Wait for response, with timeout
                if self.check_timeout(t) {
                    return Ok(0);
                }
            },
            _ => {},
        }

        let (pkt, bytes_read) = match read_packet(self, buf) {
            Ok(t) => { t },
            Err(e @ OssuaryError::WouldBlock(_)) => {
                return Err(e);
            }
            Err(e) => {
                self.reset_state(Some(e.clone()));
                return Err(e);
            }
        };

        match pkt.kind() {
            PacketType::Reset => {
                match self.state {
                    ConnectionState::ResetWait => {},
                    _ => {
                        self.reset_state(None);
                        self.state = ConnectionState::Resetting(false);
                        return Err(OssuaryError::ConnectionReset(bytes_read));
                    }
                }
            },
            PacketType::Disconnect => {
                let rs_pkt = interpret_packet::<ResetPacket>(&pkt)?;
                match rs_pkt.error {
                    true => {
                        self.reset_state(Some(OssuaryError::ConnectionFailed));
                        return Err(OssuaryError::ConnectionFailed);
                    },
                    false => {
                        self.reset_state(Some(OssuaryError::ConnectionClosed));
                        return Err(OssuaryError::ConnectionClosed);
                    },
                }
            },
            _ => {},
        }

        self.remote_msg_id = self.next_msg_id(&pkt)?;

        let res: Result<ConnectionState, OssuaryError> = match self.state {
            // no-op states
            ConnectionState::Failing(_) |
            ConnectionState::Failed(_) |
            ConnectionState::Resetting(_) |
            ConnectionState::ClientRaiseUntrustedServer |
            ConnectionState::ClientWaitServerApproval => {
                Ok(self.state.clone())
            },

            // Non-receive states.  Receiving handshake data is an error.
            ConnectionState::ClientSendHandshake |
            ConnectionState::ClientSendAuthentication |
            ConnectionState::ServerSendHandshake |
            ConnectionState::Encrypted => {
                Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()))
            },

            // Received expected handshake packet
            ConnectionState::ServerWaitHandshake(_) => {
                self.recv_client_handshake(&pkt)
            },
            ConnectionState::ClientWaitHandshake(_t) => {
                self.recv_server_handshake(&pkt)
            },
            ConnectionState::ServerWaitAuthentication(_t) => {
                self.recv_client_auth(&pkt)
            },

            // Received expected reset packet
            ConnectionState::ResetWait => {
                match pkt.kind() {
                    PacketType::Reset => {
                        self.remote_msg_id = 0;
                        match self.conn_type {
                            ConnectionType::Client => Ok(ConnectionState::ClientSendHandshake),
                            _ => Ok(ConnectionState::ServerWaitHandshake(std::time::SystemTime::now())),
                        }
                    },
                    _ => {
                        Ok(self.state.clone())
                    },
                }
            }
        };
        match res {
            Ok(s) => {
                self.state = s;
                Ok(bytes_read)
            },
            Err(e) => {
                self.reset_state(None);
                Err(e)
            }
        }
    }

    /// Indicate if handshake has timed out, and reset state if it has
    /// Resetting the state will trigger a reset packet to be sent.
    fn check_timeout(&mut self, t: std::time::SystemTime) -> bool {
        if let Ok(dur) = t.elapsed() {
            if dur.as_secs() > MAX_HANDSHAKE_WAIT_TIME {
                self.reset_state(None);
                return true
            }
        }
        false
    }

    /// Received packet, expecting ClientHandshake
    fn recv_client_handshake(&mut self, pkt: &NetworkPacket) -> Result<ConnectionState, OssuaryError> {
        match pkt.kind() {
            PacketType::ClientHandshake => {},
            _ => {
                return Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()));
            }
        }
        let inner_pkt = ClientHandshakePacket::from_packet(&pkt)?;
        self.add_remote_key(&inner_pkt.public_key, &inner_pkt.nonce);
        self.remote_auth = AuthKeyMaterial {
            challenge: Some(inner_pkt.challenge),
            public_key: None,
            signature: None,
            secret_key: None,
        };
        Ok(ConnectionState::ServerSendHandshake)
    }

    /// Received packet, expecting ServerHandshake
    fn recv_server_handshake(&mut self, pkt: &NetworkPacket) -> Result<ConnectionState, OssuaryError> {
        match pkt.kind() {
            PacketType::ServerHandshake => {},
            _ => {
                return Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()));
            }
        }
        let inner_pkt = ServerHandshakePacket::from_packet(&pkt)?;

        self.add_remote_key(&inner_pkt.public_key, &inner_pkt.nonce);
        let nonce: &[u8] = &inner_pkt.nonce;
        let session = self.local_key.session.as_ref().map(|s| s.as_bytes()).unwrap_or(&[0u8; KEY_LEN]);
        let mut plaintext: [u8; SERVER_HANDSHAKE_SUBPACKET_LEN] = [0u8; SERVER_HANDSHAKE_SUBPACKET_LEN];

        let _ = decrypt_to_bytes(session, &nonce, &inner_pkt.subpacket, &mut plaintext)?;
        let enc_pkt = ServerEncryptedHandshakePacket::from_bytes(&plaintext)?;
        let pubkey = PublicKey::from_bytes(&enc_pkt.public_key)?;
        let signature = Signature::from_bytes(&enc_pkt.signature)?;

        // All servers should have an auth key set, so
        // these parameters should be non-zero and the
        // signature should verify.
        if is_zero(&enc_pkt.challenge) || is_zero(&enc_pkt.signature) || is_zero(&enc_pkt.public_key) {
            // Parameters must be non-zero
            return Err(OssuaryError::InvalidSignature);
        }

        // This is the first encrypted message, so the nonce has not changed yet
        let mut sign_data = [0u8; KEY_LEN + NONCE_LEN + CHALLENGE_LEN];
        sign_data[0..KEY_LEN].copy_from_slice(&inner_pkt.public_key);
        sign_data[KEY_LEN..KEY_LEN+NONCE_LEN].copy_from_slice(&nonce);
        sign_data[KEY_LEN+NONCE_LEN..].copy_from_slice(&self.local_auth.challenge.unwrap_or([0u8; CHALLENGE_LEN]));
        let _ = pubkey.verify(&sign_data, &signature)?;

        self.remote_auth = AuthKeyMaterial {
            challenge: Some(enc_pkt.challenge),
            public_key: Some(pubkey),
            signature: Some(enc_pkt.signature),
            secret_key: None,
        };
        let _ = self.remote_key.as_mut().map(|k| increment_nonce(&mut k.nonce));

        match self.authorized_keys.contains(&enc_pkt.public_key) {
            true => Ok(ConnectionState::ClientSendAuthentication),
            false => Ok(ConnectionState::ClientRaiseUntrustedServer),
        }
    }

    /// Received packet, expecting ClientAuthentication
    fn recv_client_auth(&mut self, pkt: &NetworkPacket) -> Result<ConnectionState, OssuaryError> {
        match pkt.kind() {
            PacketType::ClientAuthentication => {},
            _ => {
                return Err(OssuaryError::InvalidPacket("Received unexpected handshake packet.".into()));
            },
        }
        let inner_pkt = ClientAuthenticationPacket::from_packet(&pkt)?;
        let session = self.local_key.session.as_ref().map(|s| s.as_bytes()).unwrap_or(&[0u8; KEY_LEN]);
        let nonce: &[u8] = self.remote_key.as_ref().map(|k| &k.nonce).unwrap_or(&[0u8; NONCE_LEN]);
        let mut plaintext: [u8; CLIENT_AUTH_SUBPACKET_LEN] = [0u8; CLIENT_AUTH_SUBPACKET_LEN];

        let _ = decrypt_to_bytes(session, &nonce, &inner_pkt.subpacket, &mut plaintext)?;
        let enc_pkt = ClientEncryptedAuthenticationPacket::from_bytes(&plaintext)?;

        let sig: &[u8] = &enc_pkt.signature;
        let pubkey = PublicKey::from_bytes(&enc_pkt.public_key)?;
        match self.conn_type {
            ConnectionType::AuthenticatedServer => {
                let challenge = self.local_auth.challenge.unwrap_or([0u8; CHALLENGE_LEN]);
                let signature = Signature::from_bytes(&sig)?;
                if is_zero(&challenge) || is_zero(sig) || is_zero(&enc_pkt.public_key) {
                    // Parameters must be non-zero
                    return Err(OssuaryError::InvalidSignature);
                }

                // This is the first encrypted message, so the nonce has not changed yet
                let mut sign_data = [0u8; KEY_LEN + NONCE_LEN + CHALLENGE_LEN];
                sign_data[0..KEY_LEN].copy_from_slice(self.remote_key.as_ref().map(|k| &k.public).unwrap_or(&[0u8; KEY_LEN]));
                sign_data[KEY_LEN..KEY_LEN+NONCE_LEN].copy_from_slice(&nonce);
                sign_data[KEY_LEN+NONCE_LEN..].copy_from_slice(&challenge);
                let _ = pubkey.verify(&sign_data, &signature)?;

                // Ensure this key is permitted to connect
                if self.authorized_keys.contains(&enc_pkt.public_key) == false {
                    return Err(OssuaryError::InvalidKey);
                }
            }
            _ => {},
        }
        self.remote_auth.signature = Some(enc_pkt.signature);
        self.remote_auth.public_key = Some(pubkey);
        let _ = self.remote_key.as_mut().map(|k| increment_nonce(&mut k.nonce));
        Ok(ConnectionState::Encrypted)
    }

    /// Sign remote challenge with local public key and nonce
    fn sign_remote_challenge(&self) -> [u8; SIGNATURE_LEN] {
        let pubkey = &self.local_key.public;
        let nonce = &self.local_key.nonce;
        let challenge = &self.remote_auth.challenge.unwrap_or([0u8; CHALLENGE_LEN]);
        if pubkey.len() != KEY_LEN || nonce.len() != NONCE_LEN || challenge.len() != CHALLENGE_LEN {
            return [0u8; SIGNATURE_LEN];
        }
        match &self.local_auth.secret_key {
            Some(s) => {
                let mut sign_data = [0u8; KEY_LEN + NONCE_LEN + CHALLENGE_LEN];
                sign_data[0..KEY_LEN].copy_from_slice(pubkey);
                sign_data[KEY_LEN..KEY_LEN+NONCE_LEN].copy_from_slice(nonce);
                sign_data[KEY_LEN+NONCE_LEN..].copy_from_slice(challenge);
                let server_public = self.local_auth.public_key.unwrap_or_default();
                let exp_key = ExpandedSecretKey::from(s);
                exp_key.sign(&sign_data, &server_public).to_bytes()
            },
            None => [0; SIGNATURE_LEN],
        }
    }
}

fn encrypt_to_bytes(session_key: &[u8], nonce: &[u8],
                    data: &[u8], mut out: &mut [u8]) -> Result<usize, OssuaryError> {
    let aad = [];
    let mut ciphertext = Vec::with_capacity(data.len());
    let tag = encrypt(session_key,
                      nonce,
                      &aad,
                      data,
                      &mut ciphertext)?;
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

fn decrypt_to_bytes(session_key: &[u8], nonce: &[u8],
                    data: &[u8], mut out: &mut [u8]) -> Result<usize, OssuaryError> {
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
            &mut out)?;
    Ok(ciphertext.len())
}

fn is_zero(data: &[u8]) -> bool {
    data.iter().all(|x| *x == 0)
}
