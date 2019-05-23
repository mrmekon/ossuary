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

/// Write a packet from OssuaryConnection's internal storage to the out buffer.
///
/// All packets are buffered to internal storage before writing, so this is
/// the function responsible for putting all packets "on the wire".
///
/// On success, returns the number of bytes written to the output buffer
pub(crate) fn write_stored_packet<T,U>(conn: &mut OssuaryConnection,
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

/// Write a packet to the OssuaryConnection's internal packet buffer
///
/// All packets are buffered internally because there is no guarantee that a
/// complete packet can be written without blocking, and Ossuary is a non-
/// blocking library.
///
/// On success, returns the number of bytes written to the output buffer.
pub(crate) fn write_packet<T,U>(conn: &mut OssuaryConnection,
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

impl OssuaryConnection {
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
        increment_nonce(&mut self.local_key.nonce);

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
                    match pkt.kind() {
                        PacketType::Reset => {},
                        _ => {
                            let msg_id = pkt.header.msg_id;
                            println!("Message gap detected.  Restarting connection. ({} != {})",
                                     msg_id, self.remote_msg_id);
                            self.reset_state(None);
                            return Err(OssuaryError::InvalidPacket("Message ID mismatch".into()))
                        },
                    }
                }
                self.remote_msg_id = pkt.header.msg_id + 1;

                match pkt.kind() {
                    PacketType::Reset => {
                        self.reset_state(None);
                        self.state = ConnectionState::Resetting(false);
                        return Err(OssuaryError::ConnectionReset(bytes_read));
                    },
                    PacketType::Disconnect => {
                        self.reset_state(Some(OssuaryError::ConnectionFailed));
                        return Err(OssuaryError::ConnectionFailed);
                    },
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
                                let _ = self.remote_key.as_mut().map(|k| increment_nonce(&mut k.nonce));
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
