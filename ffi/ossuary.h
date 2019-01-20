#ifndef _OSSUARY_H

#include <stdint.h>

typedef struct ConnectionContext ConnectionContext;

typedef enum {
  CONN_TYPE_CLIENT = 0x00,
  CONN_TYPE_AUTHENTICATED_SERVER = 0x01,
  CONN_TYPE_UNAUTHENTICATED_SERVER = 0x02,
} connection_type_t;

ConnectionContext *ossuary_create_connection(connection_type_t type);
int32_t ossuary_destroy_connection(ConnectionContext **conn);
int32_t ossuary_set_secret_key(ConnectionContext *conn, uint8_t key[32]);
int32_t ossuary_set_authorized_keys(ConnectionContext *conn, uint8_t *key[], uint8_t count);
int32_t ossuary_recv_handshake(ConnectionContext *conn,
                               uint8_t *in_buf, uint16_t *in_buf_len);
int32_t ossuary_send_handshake(ConnectionContext *conn,
                               uint8_t *out_buf, uint16_t *out_buf_len);
int32_t ossuary_handshake_done(ConnectionContext *conn);
int32_t ossuary_send_data(ConnectionContext *conn,
                          uint8_t *in_buf, uint16_t in_buf_len,
                          uint8_t *out_buf, uint16_t *out_buf_len);
int32_t ossuary_recv_data(ConnectionContext *conn,
                  uint8_t *in_buf, uint16_t *in_buf_len,
                  uint8_t *out_buf, uint16_t *out_buf_len);

#define _OSSUARY_H
#endif
