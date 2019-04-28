#ifndef _OSSUARY_H

#include <stdint.h>

typedef struct OssuaryConnection OssuaryConnection;

typedef enum {
  CONN_TYPE_CLIENT = 0x00,
  CONN_TYPE_AUTHENTICATED_SERVER = 0x01,
  CONN_TYPE_UNAUTHENTICATED_SERVER = 0x02,
} connection_type_t;

OssuaryConnection *ossuary_create_connection(connection_type_t type);
int32_t ossuary_destroy_connection(OssuaryConnection **conn);
int32_t ossuary_set_secret_key(OssuaryConnection *conn, uint8_t key[32]);
int32_t ossuary_set_authorized_keys(OssuaryConnection *conn, uint8_t *key[], uint8_t count);
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
