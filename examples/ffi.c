#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "ossuary.h"

uint8_t client_buf[512];
uint8_t server_buf[512];

uint8_t secret_key[] = {
  0x10, 0x86, 0x6e, 0xc4, 0x8a, 0x11, 0xf3, 0xc5,
  0x6d, 0x77, 0xa6, 0x4b, 0x2f, 0x54, 0xaa, 0x06,
  0x6c, 0x0c, 0xb4, 0x75, 0xd8, 0xc8, 0x7d, 0x35,
  0xb4, 0x91, 0xee, 0xd6, 0xac, 0x0b, 0xde, 0xbc
};

uint8_t public_key[32] = {
  0xbe, 0x1c, 0xa0, 0x74, 0xf4, 0xa5, 0x8b, 0xbb,
  0xd2, 0x62, 0xa7, 0xf9, 0x52, 0x3b, 0x6f, 0xb0,
  0xbb, 0x9e, 0x86, 0x62, 0x28, 0x7c, 0x33, 0x89,
  0xa2, 0xe1, 0x63, 0xdc, 0x55, 0xde, 0x28, 0x1f
};

uint8_t *authorized_keys[] = {
  public_key,
};

int main(int argc, char **argv) {
  int client_done, server_done;
  uint16_t client_bytes, server_bytes, bytes, out_len;
  ConnectionContext *client_conn = NULL;
  ConnectionContext *server_conn = NULL;

  client_conn = ossuary_create_connection(CONN_TYPE_CLIENT);
  ossuary_set_secret_key(client_conn, secret_key);

  server_conn = ossuary_create_connection(CONN_TYPE_AUTHENTICATED_SERVER);
  ossuary_set_authorized_keys(server_conn, authorized_keys, 1);

  memset(client_buf, 0, sizeof(client_buf));
  memset(server_buf, 0, sizeof(server_buf));

  // Client and server send handshakes
  int count = 0;
  do {
    client_done = ossuary_handshake_done(client_conn);
    server_done = ossuary_handshake_done(server_conn);
    printf("done: %d %d\n", client_done, server_done);

    if (!client_done) {
      client_bytes = sizeof(client_buf);
      ossuary_send_handshake(client_conn, client_buf, &client_bytes);
      printf("client send handshake bytes: %d\n", client_bytes);

      if (client_bytes) {
        ossuary_recv_handshake(server_conn, client_buf, &client_bytes);
        printf("server recv handshake bytes: %d\n", client_bytes);
      }
    }

    if (!server_done) {
      server_bytes = sizeof(server_buf);
      ossuary_send_handshake(server_conn, server_buf, &server_bytes);
      printf("server send handshake bytes: %d\n", server_bytes);

      if (server_bytes) {
        ossuary_recv_handshake(client_conn, server_buf, &server_bytes);
        printf("client recv handshake bytes: %d\n", server_bytes);
      }
    }

    //if (++count == 8) break;
    usleep(100000);
  } while (!client_done || !server_done);

  memset(client_buf, 0, sizeof(client_buf));
  memset(server_buf, 0, sizeof(server_buf));

  // Server sends encrypted data
  bytes = snprintf((char*)server_buf, sizeof(server_buf), "hello world");
  bytes = ossuary_send_data(server_conn, server_buf, bytes, client_buf, sizeof(client_buf));
  printf("server send data bytes: %d\n", bytes);

  // Client receives decrypted data
  out_len = sizeof(client_buf);
  bytes = ossuary_recv_data(client_conn, client_buf, bytes, client_buf, &out_len);
  printf("client recv data bytes: %d\n", bytes);
  printf("decrypted: %s\n", client_buf);

  ossuary_destroy_connection(&client_conn);
  ossuary_destroy_connection(&server_conn);
}
