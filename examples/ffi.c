#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include "ossuary.h"

uint8_t client_buf[256];
uint8_t server_buf[256];

int main(int argc, char **argv) {
  int client_done, server_done;
  uint16_t client_bytes, server_bytes, bytes;
  ConnectionContext *client_conn = NULL;
  ConnectionContext *server_conn = NULL;
  client_conn = ossuary_create_connection(0);
  server_conn = ossuary_create_connection(1);

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
  bytes = ossuary_recv_data(client_conn, client_buf, bytes, client_buf, sizeof(client_buf));
  printf("client recv data bytes: %d\n", bytes);
  printf("decrypted: %s\n", client_buf);

  ossuary_destroy_connection(&client_conn);
  ossuary_destroy_connection(&server_conn);
}
