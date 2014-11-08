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

time_t ipcookie_get_timestamp_curr(ipcookie_state_t *state, time_t now) {
  /* we need a biased timestamp to avoid everyone in the world synchronizing */
  time_t biased_now = now - state->time_bias;
  /* zero out the LSBs of the biased timestamp */
  return (biased_now - (biased_now % (1 << (1+state->halflife_log2))));
}

void ipcookie_set_stateless_with_timestamp(ipcookie_state_t *state,
                       ipcookie_t *target_cookie, struct in6_addr *peer, time_t now) {
  /* strong PRF(state->*, peer, now) needs to go here */
}

ipcookie_match_enum_t ipcookie_verify_stateless(ipcookie_state_t *state,
                                        ipcookie_t *test_cookie, struct in6_addr *src) {
  time_t now = time(NULL);
  time_t good_timestamp = ipcookie_get_timestamp_curr(state, now);
  ipcookie_t good_cookie;
  ipcookie_set_stateless_with_timestamp(state, &good_cookie, src, good_timestamp);
  if (!memcmp(&good_cookie, test_cookie, sizeof(ipcookie_t))) {
    return IPCOOKIE_MATCH_CURR;
  } else {
    good_timestamp -= (1 << state->halflife_log2);
    ipcookie_set_stateless_with_timestamp(state, &good_cookie, src, good_timestamp);
    if (!memcmp(&good_cookie, test_cookie, sizeof(ipcookie_t))) {
      return IPCOOKIE_MATCH_PREV;
    }
  }
  return IPCOOKIE_NOMATCH;
}

void ipcookie_set_stateless(ipcookie_state_t *state, ipcookie_t *target_cookie, struct in6_addr *peer) {
  time_t now = time(NULL);
  ipcookie_set_stateless_with_timestamp(state, target_cookie, peer,
                          ipcookie_get_timestamp_curr(state, now));
}

