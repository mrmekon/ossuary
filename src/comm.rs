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

use std::convert::TryInto;

/// Read a complete network packet from the input stream.
///
/// On success, returns a NetworkPacket struct containing the header and data,
/// and a `usize` indicating how many bytes were consumed from the input buffer.
pub(crate) fn read_packet<T,U>(conn: &mut OssuaryConnection,
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
            return Err(OssuaryError::InvalidPacket("Oversized packet".into()));
        }
        return Err(OssuaryError::WouldBlock(bytes_read));
    }
    let buf: Box<[u8]> = (&conn.read_buf[header_size..header_size+packet_len])
        .to_vec().into_boxed_slice();
    let excess = conn.read_buf_used - header_size - packet_len;
    let start = header_size + packet_len;
    conn.read_buf.copy_within(start..start + excess, 0);
    conn.read_buf_used = excess;
    Ok((NetworkPacket {
        header: hdr,
        data: buf,
    },
    header_size + packet_len))
}

/// Write a packet from OssuaryConnection's internal storage to the out buffer.
///
/// All packets are buffered to internal storage before writing, so this is
/// the function responsible for putting all packets "on the wire".
///
/// On success, returns the number of bytes written to the output buffer
pub(crate) fn write_stored_packet<T>(conn: &mut OssuaryConnection,
                                     stream: &mut T) -> Result<usize, OssuaryError>
where T: std::io::Write {
    let mut written = 0;
    while written < conn.write_buf_used {
        match stream.write(&conn.write_buf[written..conn.write_buf_used]) {
            Ok(w) => {
                written += w;
            },
            Err(e) => {
                if written > 0 && written < conn.write_buf_used {
                    conn.write_buf
                        .copy_within(written..written + conn.write_buf_used, 0);
                }
                conn.write_buf_used -= written;
                return Err(e.into());
            },
        }
    }
    conn.write_buf_used = 0;
    Ok(written)
}

/// Write a packet to the OssuaryConnection's internal packet buffer
///
/// All packets are buffered internally because there is no guarantee that a
/// complete packet can be written without blocking, and Ossuary is a non-
/// blocking library.
///
/// On success, returns the number of bytes written to the output buffer.
pub(crate) fn write_packet<T>(conn: &mut OssuaryConnection,
                                stream: &mut T, data: &[u8],
                                kind: PacketType) -> Result<usize, OssuaryError>
where T: std::io::Write {
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

impl OssuaryConnection {
    /// Encrypts data into a packet suitable for sending over the network
    ///
    /// The caller provides unencrypted plaintext data, in any format, in the
    /// `in_buf` buffer.  `send_data()` encrypts it and writes it in the proper
    /// packet format into `out_buf`.
    ///
    /// This is the core function for data transmission via ossuary.  All data
    /// to be sent over an Ossuary connection should pass through this function.
    ///
    /// Note that Ossuary does not perform network operations itself.  It is the
    /// caller's responsibility to put the written data on the wire.  However,
    /// you may pass a 'buf' that does this automatically, such as a TcpStream.
    ///
    /// Returns the number of bytes written to `out_buf`, or an error.
    ///
    /// You must handle [`OssuaryError::WouldBlock`], which is a recoverable
    /// error, but indicates that some bytes were written to the buffer.  If any
    /// bytes are written to `out_buf`, it can be assumed that all of `in_buf`
    /// was consumed.  In the event of a `WouldBlock` error, you can either
    /// continue calling `send_data()` with the next data to be sent, or you can
    /// use [`OssuaryConnection::flush()`] to explicitly finish writing the
    /// packet.
    pub fn send_data<T,U>(&mut self,
                          in_buf: &[u8],
                          mut out_buf: T) -> Result<usize, OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Write {
        // Try to send any unsent buffered data
        match write_stored_packet(self, out_buf.deref_mut()) {
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
                return Err(OssuaryError::InvalidKey);
            }
        };
        let tag = match encrypt(session_key.as_bytes(),
                                &self.local_key.nonce, &aad, in_buf, &mut ciphertext) {
            Ok(t) => t,
            Err(_) => {
                self.reset_state(None);
                return Err(OssuaryError::InvalidKey);
            }
        };
        increment_nonce(&mut self.local_key.nonce);

        let pkt: EncryptedPacket = EncryptedPacket {
            tag_len: tag.len() as u16,
            data_len: ciphertext.len() as u16,
        };
        let mut buf: Vec<u8>= vec![];
        buf.extend(struct_as_slice(&pkt));
        buf.extend(&ciphertext);
        buf.extend(&tag);
        let written = write_packet(self, out_buf.deref_mut(), &buf,
                                   PacketType::EncryptedData)?;
        Ok(written)
    }

    /// Decrypts data from a packet received from a remote host
    ///
    /// The caller provides encrypted data from a remote host in the `in_buf`
    /// buffer.  `recv_data()` decrypts it and writes the plaintext result into
    /// `out_buf`.
    ///
    /// This is the core function for data transmission via ossuary.  All data
    /// received over an Ossuary connection should pass through this function.
    ///
    /// Returns the number of bytes written to `out_buf`, or an error.
    ///
    /// You must handle [`OssuaryError::WouldBlock`], which is a recoverable
    /// error, but indicates that some bytes were read from `in_buf`.  This
    /// indicates that an incomplete packet was received.
    pub fn recv_data<T,U,R,V>(&mut self,
                              in_buf: T,
                              mut out_buf: R) -> Result<(usize, usize), OssuaryError>
    where T: std::ops::DerefMut<Target = U>,
          U: std::io::Read,
          R: std::ops::DerefMut<Target = V>,
          V: std::io::Write {
        let mut bytes_read: usize = 0;
        match self.state {
            ConnectionState::Failed(_) => { return Ok((0,0)); }
            ConnectionState::Encrypted => {},
            _ => {
                return Err(OssuaryError::InvalidPacket(
                    "Encrypted channel not established.".into()));
            }
        }

        let (pkt, bytes) = match read_packet(self, in_buf) {
            Ok(t) => { t },
            Err(e @ OssuaryError::WouldBlock(_)) => {
                return Err(e);
            }
            Err(e) => {
                self.reset_state(Some(e.clone()));
                return Err(e);
            }
        };
        bytes_read += bytes;
        self.remote_msg_id = self.next_msg_id(&pkt)?;

        let result: Result<usize, OssuaryError> = match pkt.kind() {
            PacketType::Reset => {
                 // return on error, since this resets the state in a special way
                Ok(self.handle_reset_packet(bytes_read)?)
            },
            PacketType::Disconnect => { self.handle_disconnect_packet(&pkt) },
            PacketType::EncryptedData => { self.recv_encrypted_data(&pkt, out_buf.deref_mut()) },
            _ => {
                Err(OssuaryError::InvalidPacket(
                    "Received non-encrypted data on encrypted channel.".into()))
            },
        };

        match result {
            Ok(bytes_written) => Ok((bytes_read, bytes_written)),
            Err(e) => {
                self.reset_state(None);
                // bytes_read not returned on error, but will be consumed again
                // when the handshake restarts.
                Err(e)
            }
        }
    }

    fn recv_encrypted_data<T>(&mut self, pkt: &NetworkPacket, out_buf: &mut T) -> Result<usize, OssuaryError>
    where T: std::io::Write {
        let (data_pkt, rest) = interpret_packet_extra::<EncryptedPacket>(&pkt)?;
        let session_key = match &self.local_key.session {
            Some(k) => k,
            None => { return Err(OssuaryError::InvalidKey); },
        };
        let remote_nonce = self.remote_key.as_ref().map(|k| &k.nonce).unwrap_or(&[0u8; NONCE_LEN]);
        let ciphertext = &rest[..data_pkt.data_len as usize];
        let tag = &rest[data_pkt.data_len as usize..];
        let aad = [];
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        decrypt(session_key.as_bytes(),
                remote_nonce,
                &aad, &ciphertext, &tag, &mut plaintext)?;
        match out_buf.write(&plaintext) {
            Ok(w) => {
                let _ = self.remote_key.as_mut().map(|k| increment_nonce(&mut k.nonce));
                Ok(w)
            },
            Err(e) => Err(e.into()),
        }
    }

    /// Write any cached encrypted data waiting to be sent
    ///
    /// If a previous call to [`OssuaryConnection::send_data`] was unable to
    /// write out all of its data, the remaining data is cached internally.  It
    /// can be explicitly flushed by calling this function until it returns 0.
    ///
    /// After each call, it is the caller's responsibility to put the written
    /// data onto the network, unless `out_buf` is an object that handles that
    /// implicitly, such as a TcpStream.
    pub fn flush<R,V>(&mut self,
                      mut out_buf: R) -> Result<usize, OssuaryError>
    where R: std::ops::DerefMut<Target = V>,
          V: std::io::Write {
        return write_stored_packet(self, out_buf.deref_mut());
    }
}
