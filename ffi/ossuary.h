#ifndef _OSSUARY_H

#include <stdint.h>

typedef struct ConnectionContext ConnectionContext;

ConnectionContext *ossuary_create_connection(uint8_t is_server);
int32_t ossuary_destroy_connection(ConnectionContext **conn);
int32_t ossuary_recv_handshake(ConnectionContext *conn,
                               uint8_t *in_buf, uint16_t *in_buf_len);
int32_t ossuary_send_handshake(ConnectionContext *conn,
                               uint8_t *out_buf, uint16_t *out_buf_len);
uint8_t ossuary_handshake_done(ConnectionContext *conn);
int32_t ossuary_send_data(ConnectionContext *conn,
                          uint8_t *in_buf, uint16_t in_buf_len,
                          uint8_t *out_buf, uint16_t out_buf_len);
int32_t ossuary_recv_data(ConnectionContext *conn,
                  uint8_t *in_buf, uint16_t in_buf_len,
                  uint8_t *out_buf, uint16_t out_buf_len);

#define _OSSUARY_H
#endif
