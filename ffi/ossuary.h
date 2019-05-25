#ifndef _OSSUARY_H

#include <stdint.h>

typedef struct OssuaryConnection OssuaryConnection;

typedef enum {
  OSSUARY_CONN_TYPE_CLIENT = 0x00,
  OSSUARY_CONN_TYPE_AUTHENTICATED_SERVER = 0x01,
  OSSUARY_CONN_TYPE_UNAUTHENTICATED_SERVER = 0x02,
} ossuary_conn_type_t;

typedef enum {
  OSSUARY_ERR_OTHER = -1,
  OSSUARY_ERR_WOULDBLOCK = -64,
  OSSUARY_ERR_UNTRUSTED_SERVER = -65,
} ossuary_error_t;

OssuaryConnection *ossuary_create_connection(ossuary_conn_type_t type, const uint8_t auth_key[32]);
int32_t ossuary_destroy_connection(OssuaryConnection **conn);
int32_t ossuary_set_secret_key(OssuaryConnection *conn, const uint8_t key[32]);
int32_t ossuary_add_authorized_key(OssuaryConnection *conn, const uint8_t key[32]);
int32_t ossuary_add_authorized_keys(OssuaryConnection *conn, uint8_t *key[], uint8_t count);
int32_t ossuary_remote_public_key(OssuaryConnection *conn,
                                  uint8_t *key_buf, uint16_t key_buf_len);
int32_t ossuary_generate_auth_keypair(uint8_t *secret_buf, uint16_t secret_buf_len,
                                      uint8_t *public_buf, uint16_t public_buf_len);
int32_t ossuary_recv_handshake(OssuaryConnection *conn,
                               uint8_t *in_buf, uint16_t *in_buf_len);
int32_t ossuary_send_handshake(OssuaryConnection *conn,
                               uint8_t *out_buf, uint16_t *out_buf_len);
int32_t ossuary_handshake_done(OssuaryConnection *conn);
int32_t ossuary_send_data(OssuaryConnection *conn,
                          uint8_t *in_buf, uint16_t in_buf_len,
                          uint8_t *out_buf, uint16_t *out_buf_len);
int32_t ossuary_recv_data(OssuaryConnection *conn,
                          uint8_t *in_buf, uint16_t *in_buf_len,
                          uint8_t *out_buf, uint16_t *out_buf_len);

#define _OSSUARY_H
#endif
