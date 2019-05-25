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
#include <arpa/inet.h>
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
  OssuaryConnection *client_conn = NULL;
  int sock;
  int flags;
  int read_len;
  int handshake;
  uint16_t read_buf_len;
  uint16_t write_buf_len;
  printf("Connecting to localhost port 9981...\n");
  if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    fprintf(stderr, "ERROR: could not create IPv4 socket\n");
    exit(1);
  }
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(9981);
  inaddr.s_addr = inet_addr("127.0.0.1");
  addr.sin_addr = inaddr;

  if (connect(sock, (const struct sockaddr*)&addr, sizeof(struct sockaddr_in)) < 0) {
    fprintf(stderr, "ERROR: could not connect to 127.0.0.1:9981\n");
    exit(1);
  }

  if ((client_conn = ossuary_create_connection(OSSUARY_CONN_TYPE_CLIENT, NULL)) == NULL) {
    fprintf(stderr, "ERROR: could not create Ossuary connection\n");
    exit(1);
  }
  ossuary_add_authorized_key(client_conn, public_key);

  flags = fcntl(sock, F_GETFL, 0);
  if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
    fprintf(stderr, "ERROR: could not set non-blocking\n");
    exit(1);
  }

  printf("Connected!\n");
  while (1) {
    if ((read_len = read(sock, read_buf, sizeof(read_buf))) <= 0) {
      if (errno != EAGAIN) {
        fprintf(stderr, "ERROR: read failed: %d\n", read_len);
        exit(1);
      }
    }

    if ((handshake = ossuary_handshake_done(client_conn)) == 0) {
      write_buf_len = sizeof(write_buf);
      if (ossuary_send_handshake(client_conn, write_buf, &write_buf_len) < 0) {
        fprintf(stderr, "ERROR: handshake send failed\n");
        exit(1);
      }
      if (read_len > 0) {
        read_buf_len = read_len;
        if (ossuary_recv_handshake(client_conn, read_buf, &read_buf_len) < 0) {
          fprintf(stderr, "ERROR: handshake recv failed\n");
          exit(1);
        }
        memmove(read_buf, read_buf + read_buf_len, read_len - read_buf_len);
        read_buf_len = 0;
      }
    }
    else if (handshake < 0) {
      fprintf(stderr, "ERROR: handshake failed: %d\n", handshake);
      exit(1);
    }
    else {
      if (read_len > 0) {
        write_buf_len = 0;
        if (ossuary_recv_data(client_conn, read_buf, read_buf_len, write_buf, &write_buf_len) > 0) {
          memmove(read_buf, read_buf + read_buf_len, read_len - read_buf_len);
          read_buf_len = 0;
          printf("Received %d encrypted bytes\n", read_len);
          write_buf_len = 0;
        }
      }
      printf("Enter message: ");
      read_buf[0] = 0;
      gets((char *)read_buf);
      read_buf_len = strlen((char *)read_buf) + 1;
      write_buf_len = sizeof(write_buf);
      ossuary_send_data(client_conn, read_buf, read_buf_len, write_buf, &write_buf_len);
    }

    if (write_buf_len > 0) {
      if (write(sock, write_buf, write_buf_len) != write_buf_len) {
        fprintf(stderr, "ERROR: write failed\n");
        exit(1);
      }
      write_buf_len = 0;
    }
  }

  close(sock);

}
