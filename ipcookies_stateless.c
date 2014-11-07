#include <sys/types.h>
#include <sys/socket.h>
#define __APPLE_USE_RFC_3542
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <time.h>
#include <netinet/icmp6.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "ipcookies.h"

int ipcookie_verify_stateless(ipcookie_state_t *state, ipcookie_t testcookie, struct in6_addr *src) {
  /* FIXME */
  return 0;
}

void ipcookie_set_stateless(ipcookie_state_t *state, ipcookie_t *target_cookie, struct in6_addr *peer) {
  /* FIXME */
}

