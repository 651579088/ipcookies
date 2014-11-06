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


int ipcookies_shim_outbound_cookie(void *ipck, struct in6_addr *peer, void **cookie) {
  ipcookie_entry_t *ce = ipcookie_find_by_address(ipck, peer);
  if (ce) {
  } else {
  }
  return 0;
}

int ipcookies_shim_inbound_check_cookie(void *ipck, struct in6_addr *peer, void *cookie) {
  ipcookie_t *rcvd_cookie_p = cookie;
  int res = ipcookie_verify_stateless(cookie, peer);
  if (res < IPCOOKIE_MATCH_CURR) {
    /* Either no match or the match on prev cookie, build and send SET-COOKIE */
    
  }
  return res;
}

#ifndef SHIM_IPCOOKIE_LIBRARY

int main(int argc, char *argv[]) {
  return 0;
}

#endif



