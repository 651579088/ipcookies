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
  uint8_t buf[IPCOOKIES_ICMP_SIZE];
  struct icmp6_hdr *icmp = (void *)buf;
  struct icmp6_ipcookies *icmp_ipck = (void *)(icmp+1);
  ipcookie_t *rcvd_cookie_p = cookie;
  int res = ipcookie_verify_stateless(cookie, peer);

  if (res < IPCOOKIE_MATCH_CURR) {
    /* Either no match or the match on prev cookie, build and send SET-COOKIE */
    icmp->icmp6_type = ICMP6_IPCOOKIES;
    icmp->icmp6_code = ICMP6_IC_SET_COOKIE;
    memcpy(icmp_ipck->echoed_cookie, cookie, sizeof(icmp_ipck->echoed_cookie));
    ipcookie_set_stateless(&icmp_ipck->requested_cookie, peer);
    ipcookies_icmp_send(buf, peer);
  }
  return res;
}

#ifndef SHIM_IPCOOKIE_LIBRARY

int main(int argc, char *argv[]) {
  return 0;
}

#endif



