#ifndef _OSSUARY_H

#include <stdint.h>

typedef struct OssuaryConnection OssuaryConnection;

typedef enum {
  // Connection is a client
  OSSUARY_CONN_TYPE_CLIENT = 0x00,
  // Connection is a server that only permits known clients.
  OSSUARY_CONN_TYPE_AUTHENTICATED_SERVER = 0x01,
  // Connection is a server that permits any client.
  OSSUARY_CONN_TYPE_UNAUTHENTICATED_SERVER = 0x02,
} ossuary_conn_type_t;

typedef enum {
  // Most errors return this for now.
  OSSUARY_ERR_OTHER = -1,
  // Returned from recv/send functions when only a partial packet was read
  // or written.  This is not an error, but if received frequently it may
  // indicate that your buffers are too small or your connection is highly
  // fragmented.
  OSSUARY_ERR_WOULDBLOCK = -64,
  // Returned when connection is established to a remote host whose public
  // authentication key is not known.  This is an error for connections that
  // require known authentication, but can be recoverable for connections that
  // implement a Trust-On-First-Use policy.
  OSSUARY_ERR_UNTRUSTED_SERVER = -65,
} ossuary_error_t;

// Create a new Ossuary connection object
//
// This is the first Ossuary function called.  It creates a stateful context
// representing one half of an encrypted communication channel.  All subsequent
// Ossuary calls take this object as a parameter.
//
// The OssuaryConnection object is dynamically allocated, and should be relased
// with ossuary_destroy_connection() when no longer needed.
//
// It is highly recommended that you read the Rust documentation for Ossuary, in
// addition to this C API documentation.
//
// 'type'     - Specify client or server type for this end of the connection
// 'auth_key' - Specify the secret authentication key (ed25519) of this connection.
//              This may be NULL, in which case a secret key is randomly generated.
//
// Returns: Allocated connection object, or NULL on error.
//
OssuaryConnection *ossuary_create_connection(ossuary_conn_type_t type, const uint8_t auth_key[32]);

// Destroy an existing Ossuary connection object
//
// Deallocates an OssuaryConnection object created with
// ossuary_create_connection().
//
// 'conn' - A pointer to an OssuaryConnection created with ossuary_create_connection
//
void ossuary_destroy_connection(OssuaryConnection **conn);

// Change the secret authentication key for an Ossuary connection
//
// This changes the ed25519 authentication keypair that the host uses to
// identify itself during connection handshakes.  It is the same as the
// 'auth_key' parameter to ossuary_create_connection(), but this function does
// not allow NULLs.
//
// 'conn' - An OssuaryConnection allocated by ossuary_create_connection()
// 'key' - Specify the secret authentication key (ed25519) of this connection.
//
// Returns: 0 on success, -1 on failure.
//
int32_t ossuary_set_secret_key(OssuaryConnection *conn, const uint8_t key[32]);

// Add one public authentication key to the list of authorized remote hosts.
//
// Server connections with type OSSUARY_CONN_TYPE_AUTHENTICATED_SERVER only
// permit connections from clients that authorize with a known key.  Client
// connections only permit connections to servers with a known key.  This
// function adds an ed25519 public key to the list of known keys, permitting
// connections to or from a host that proves it has the matching secret key.
//
// 'conn' - An OssuaryConnection allocated by ossuary_create_connection()
// 'key'  - Ed25519 public authentication key to permit connections from
//
// Returns 0 on success, -1 on failure
//
int32_t ossuary_add_authorized_key(OssuaryConnection *conn, const uint8_t key[32]);

// Add multiple public authentication keys to the list of authorized hosts.
//
// See ossuary_add_authorized_key() for details.  This function does the same,
// but allows more than one key to be specified at a time.
//
// 'conn'  - An OssuaryConnection allocated by ossuary_create_connection()
// 'key'   - An array of 32-byte Ed25519 public keys
// 'count' - The number of 32-byte keys in 'key'
//
// Returns 0 on success, -1 on failure
//
int32_t ossuary_add_authorized_keys(OssuaryConnection *conn, uint8_t *key[], uint8_t count);

// Get the public Ed25519 authentication key of the remote host
//
// When a connection to a remote host has been established, this function
// returns the public Ed25519 authentication key of the remote side.
//
// This key becomes available during the handshake process.  In the special case
// of a client connecting to a server, when the client has not added the
// server's public key to its authorized key list with
// ossuary_add_authorized_key(), the ossuary_handshake_done() function will
// return OSSUARY_ERR_UNTRUSTED_SERVER and pause the handshake.  For clients
// that wish to use a Trust-On-First-Use (TOFU) policy, they can immediately
// call this function to get the public key, add it to the list of authorized
// keys with ossuary_add_authorized_key() if it has never been seen before, and
// the handshake will continue.
//
// 'conn'    - An OssuaryConnection allocated by ossuary_create_connection()
// 'key_buf' - A buffer of at least 32 bytes to receive the public key
// 'key_buf_len' - Size of 'key_buf' in bytes
//
// Returns 0 on success, -1 on failure
//
int32_t ossuary_remote_public_key(OssuaryConnection *conn,
                                  uint8_t *key_buf, uint16_t key_buf_len);

// Generate a random new Ed25519 authentication key pair
//
// This is a utility function for generating Ed25519 authentication keys.
// It does not require an established connection.  It can be used for initial
// generation of keypairs when configuring new hosts.
//
// 'secret_buf'     - Buffer of at least 32 bytes to receive the secret key
// 'secret_buf_len' - Size, in bytes, of 'secret_buf'
// 'public_buf'     - Buffer of at least 32 bytes to receive the public key
// 'public_buf_len' - Size, in bytes, of 'public_buf'
//
// Returns 0 on success, -1 on failure
//
int32_t ossuary_generate_auth_keypair(uint8_t *secret_buf, uint16_t secret_buf_len,
                                      uint8_t *public_buf, uint16_t public_buf_len);

// Parse connection handshake packets out of an input buffer
//
// This function is part of the handshake loop used to establish a new encrypted
// session.  When data is received from a remote host, it must be passed to this
// function if the handshake is not yet completed (ossuary_handshake_done()).
// This function parses and decrypts any handshake packets in the input and
// updates the internal state of the connection.
//
// This function 'consumes' input data, and updated 'in_buf_len' to be the
// number of bytes consumed.  The caller should take care to remove exactly
// 'in_buf_len' bytes from the beginning of 'in_buf' after calling.
//
// When a partial packet is received, this function returns
// OSSUARY_ERR_WOULDBLOCK.  Data might still be consumed in this case,
// so 'in_buf_len' is still valid.
//
// 'conn'       - An OssuaryConnection allocated by ossuary_create_connection()
// 'in_buf'     - Buffer containing data received from remote host
// 'in_buf_len' - Length of 'in_buf' in bytes
//
// Returns number of bytes consumed from 'in_buf', or OSSUARY_ERR_WOULDBLOCK
// if a partial packet was received.  In either case, 'in_buf_len' is set to
// the number of bytes to remove from the beginning of 'in_buf'.  Returns
// other values <0 on error.
//
int32_t ossuary_recv_handshake(OssuaryConnection *conn,
                               uint8_t *in_buf, uint16_t *in_buf_len);

// Get handshake packet to send to remote host
//
// This function is part of the handshake loop used to establish a new encrypted
// session.  When the local side of the connection is ready to send another
// handshake packet, this function fills a buffer with the encrypted data
// that needs to be sent to the remote host.  It should continue to be called
// in a loop until the handshake is done (ossuary_handshake_done()).
//
// It is up to the caller to push the data in 'out_buf' to the remote host via
// whatever communication transport is in use.
//
// When a partial packet is written, this function returns
// OSSUARY_ERR_WOULDBLOCK.  Data might still be written to 'out_buf'  in this
// case, so 'out_buf_len' is still valid.

// 'conn'        - An OssuaryConnection allocated by ossuary_create_connection()
// 'out_buf'     - Buffer to receive data to send to remote host
// 'out_buf_len' - Size of 'out_buf' in bytes
//
// Returns number of bytes written to 'out_buf', or OSSUARY_ERR_WOULDBLOCK
// if a partial packet was written.  In either case, 'out_buf_len' is set to
// the number of bytes to send.  Returns other values <0 on error.
//
int32_t ossuary_send_handshake(OssuaryConnection *conn,
                               uint8_t *out_buf, uint16_t *out_buf_len);

// Returns whether the handshake process has completed
//
// Ossuary's encrypted connections are established via a 'handshake' process,
// which involves checking in a loop of the handshake is completed by calling
// this function, and if it is not then data received from the transport layer
// should be fed in via ossuary_recv_handshake(), and data returned by
// ossuary_send_handshake() should be sent out on the transport layer.
//
// As Ossuary can drop back into handshake mode if a connection is interrupted
// or corrupted, the calling application should *always* call this function on
// every loop.
//
// If an error has occurred during the handshake process, this function
// can return an error code.
//
// 'conn'    - An OssuaryConnection allocated by ossuary_create_connection()
//
// Returns: 0 if handshake is not finished, 1 if handshake is finished,
//          error code <0 on error.  OSSUARY_ERR_UNTRUSTED_SERVER can be
//          returned if the remote host's authentication key is not known, and
//          a Trust-On-First-Use policy can be implemented.
//
int32_t ossuary_handshake_done(OssuaryConnection *conn);

// Encrypt data for transmisssion over an established Ossuary connection
//
// This is the main function for transmitting encrypted data.  When an
// application has data to transmit to the remote host, it passes it into this
// function and receives back an encrypted block of data suitable for
// transmission.
//
// Should only be called if ossuary_handshake_done() returns 1.
//
// 'conn'        - An OssuaryConnection allocated by ossuary_create_connection()
// 'in_buf'      - Buffer of unencrypted data to encrypt with Ossuary
// 'in_buf_len'  - Length of 'in_buf' in bytes
// 'out_buf'     - Buffer to receive encrypted data
// 'out_buf_len' - Size of 'out_buf' in bytes.  Updated to be number of bytes
//                 written to 'out_buf'.
//
// Returns number of bytes written if a full packet fit in 'out_buf', or
// OSSUARY_ERR_WOULDBLOCK if a partial packet was written.  Returns a different
// error code <0 on error.
//
int32_t ossuary_send_data(OssuaryConnection *conn,
                          uint8_t *in_buf, uint16_t in_buf_len,
                          uint8_t *out_buf, uint16_t *out_buf_len);

// Decrypt data that was received over an established Ossuary connection
//
// This is the main function for receiving encrypted data.  When an application
// has received data from a remote host, it passes it into this function and
// receives back an unencrypted block of data suitable for internal use.
//
// Should only be called if ossuary_handshake_done() returns 1.
//
// 'conn'        - An OssuaryConnection allocated by ossuary_create_connection()
// 'in_buf'      - Buffer of encrypted data to decrypt with Ossuary
// 'in_buf_len'  - Length of 'in_buf' in bytes.  Updated to be number of bytes
//                 read from 'in_buf'.
// 'out_buf'     - Buffer to receive decrypted data
// 'out_buf_len' - Size of 'out_buf' in bytes.  Updated to be number of bytes
//                 written to 'out_buf'.
//
// Returns number of bytes read if a full packet was read from 'in_buf', or
// OSSUARY_ERR_WOULDBLOCK if a partial packet was read.  Returns a different
// error code <0 on error.
//
int32_t ossuary_recv_data(OssuaryConnection *conn,
                          uint8_t *in_buf, uint16_t *in_buf_len,
                          uint8_t *out_buf, uint16_t *out_buf_len);

#define _OSSUARY_H
#endif
