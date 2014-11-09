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

/*
 * Very naive linear algorithms here, just for experimentation.
 */

ipcookie_entry_t *ipcookie_cache_entry_find_by_address(ipcookie_cache_t *ipck, struct in6_addr *peer) {
  ipcookie_entry_t *ce;
  ipcookie_entry_t *ce_end = ipck->entries + IPCOOKIE_CACHE_SIZE;
  for(ce = ipck->entries; ce < ce_end; ce++) {
    if(!memcmp(&ce->peer, peer, sizeof(*peer))) {
      return ce;
    }
  }
  return NULL;
}

ipcookie_entry_t *ipcookie_cache_entry_allocate(ipcookie_cache_t *ipck, struct in6_addr *peer) {
  ipcookie_entry_t *ce;
  ipcookie_entry_t *ce_end = ipck->entries + IPCOOKIE_CACHE_SIZE;
  for(ce = ipck->entries; ce < ce_end; ce++) {
    if(IN6_IS_ADDR_UNSPECIFIED(&ce->peer)) {
      return ce;
    }
  }
  return NULL;
}

