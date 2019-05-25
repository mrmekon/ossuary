#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "ossuary.h"

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

int main(int argc, char **argv) {
  uint8_t read_buf[1024];
  uint8_t write_buf[1024];
  struct sockaddr_in addr;
  struct in_addr inaddr;
  socklen_t addr_len;
  OssuaryConnection *server_conn = NULL;
  int sock;
  int conn;
  int flags;
  int client;
  int read_len;
  uint16_t read_buf_len;
  uint16_t write_buf_len;
  printf("Starting on localhost port 9981...\n");
  if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "ERROR: could not create IPv4 socket\n");
    exit(1);
  }
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(9981);
  inaddr.s_addr = 0;
  addr.sin_addr = inaddr;

  if ((conn = bind(sock, (const struct sockaddr*)&addr, sizeof(struct sockaddr_in))) < 0) {
    fprintf(stderr, "ERROR: could not bind to 127.0.0.1:9981\n");
    exit(1);
  }
  if (listen(sock, 3) < 0) {
    fprintf(stderr, "ERROR: could not listen on 127.0.0.1:9981\n");
    exit(1);
  }
  addr_len = sizeof(struct sockaddr_in);
  if ((client = accept(sock, (struct sockaddr*)&addr, &addr_len)) < 0) {
    fprintf(stderr, "ERROR: could not listen on 127.0.0.1:9981\n");
    exit(1);
  }

  if ((server_conn = ossuary_create_connection(OSSUARY_CONN_TYPE_UNAUTHENTICATED_SERVER, NULL)) == NULL) {
    fprintf(stderr, "ERROR: could not create Ossuary connection\n");
    exit(1);
  }
  ossuary_set_secret_key(server_conn, secret_key);

  flags = fcntl(client, F_GETFL, 0);
  if (fcntl(client, F_SETFL, flags | O_NONBLOCK) < 0) {
    fprintf(stderr, "ERROR: could not set non-blocking\n");
    exit(1);
  }

  printf("Connected!\n");
  while (1) {
    if ((read_len = read(client, read_buf, sizeof(read_buf))) <= 0) {
      if (errno != EAGAIN) {
        fprintf(stderr, "ERROR: read failed\n");
        exit(1);
      }
    }

    if (ossuary_handshake_done(server_conn) == 0) {
      write_buf_len = sizeof(write_buf);
      if (ossuary_send_handshake(server_conn, write_buf, &write_buf_len) < 0) {
        fprintf(stderr, "ERROR: handshake send failed\n");
        exit(1);
      }
      if (read_len > 0) {
        read_buf_len = read_len;
        if (ossuary_recv_handshake(server_conn, read_buf, &read_buf_len) < 0) {
          fprintf(stderr, "ERROR: handshake recv failed\n");
          exit(1);
        }
        memmove(read_buf, read_buf + read_buf_len, read_len - read_buf_len);
        read_buf_len = 0;
      }
    }
    else {
      if (read_len > 0) {
        read_buf_len += read_len;
        write_buf_len = sizeof(write_buf);
        if ((read_len = ossuary_recv_data(server_conn, read_buf, read_buf_len, write_buf, &write_buf_len)) > 0) {
          memmove(read_buf, read_buf + read_len, read_buf_len - read_len);
          read_buf_len -= read_len;
          if (write_buf_len > 0) {
            printf("MSG: %s\n", write_buf);
          }
          write_buf_len = 0;
          read_len = 0;
        }
      }
    }

    if (write_buf_len) {
      if (write(client, write_buf, write_buf_len) != write_buf_len) {
        fprintf(stderr, "ERROR: write failed\n");
        exit(1);
      }
      write_buf_len = 0;
    }
  }

  close(client);
  close(sock);
}
