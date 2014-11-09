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
#include "shim_ipcookies.h"

void ipcookie_entry_enter_fallback_mode(ipcookie_entry_t *ce) {
  ipcookie_entry_set_disable_cookies(ce);
  ipcookie_entry_update_mtime(ce);
  ipcookie_entry_set_lifetime_log2(ce, IPCOOKIE_FALLBACK_LT2);
}

void ipcookie_entry_enter_late_recovery_mode(ipcookie_entry_t *ce) {
  ipcookie_entry_set_expecting_setcookie(ce);
  ipcookie_entry_mtime_backdate_by_lifetime_log2(ce);
}

void ipcookie_entry_past_renew_with_cookie(ipcookie_entry_t *ce, struct in6_addr *peer, void **ret_cookie) {
  if(ipcookie_entry_isset_expecting_setcookie(ce)) {
    ipcookie_entry_enter_fallback_mode(ce);
  } else {
    ipcookie_entry_enter_late_recovery_mode(ce);
  }
}

void ipcookie_entry_within_renew_with_cookie(ipcookie_entry_t *ce) {
  /*
   * If the expecting cookie flag is not set, set it
   * and rewind the mtime so that we wait for
   * the whole recovery interval before a fallback
   * may occur.
   */
  if (!ipcookie_entry_isset_expecting_setcookie(ce)) {
    ipcookie_entry_set_expecting_setcookie(ce);
    ipcookie_entry_mtime_backdate_by_lifetime_log2(ce);
  }
}

void ipcookies_shim_outbound_ipcookie_entry_exists(ipcookie_entry_t *ce, struct in6_addr *peer, void **ret_cookie) {
  int ts_check = check_ipcookie_entry_timestamp(ce);
  if(ipcookie_entry_isset_disable_cookies(ce)) {
    switch(ts_check) {
      case IPCOOKIE_TS_STILL_VALID:
	/* do nothing */
	break;
      case IPCOOKIE_TS_RENEW_TIME:
	/* fallthrough */
      case IPCOOKIE_TS_PAST_RENEW_TIME:
	ipcookie_entry_clear_disable_cookies(ce);
	ipcookie_entry_update_mtime(ce);
	ipcookie_entry_set_lifetime_log2(ce, IPCOOKIE_TRY_LT2);
	break;
    }
  } else {
    switch(ts_check) {
      case IPCOOKIE_TS_STILL_VALID:
	/* do nothing */
	break;
      case IPCOOKIE_TS_RENEW_TIME:
	ipcookie_entry_within_renew_with_cookie(ce);
	break;
      case IPCOOKIE_TS_PAST_RENEW_TIME:
        ipcookie_entry_past_renew_with_cookie(ce, peer, ret_cookie);
	break;
    }
  }
}

ipcookie_entry_t *ipcookies_shim_outbound_no_ipcookie_entry(void *ipck, int default_use_ipcookies, struct in6_addr *peer, void **ret_cookie) {
  ipcookie_entry_t *ce = ipcookie_cache_entry_allocate(&((ipcookie_full_state_t *)ipck)->cache, peer);
  if (ce) {
    if (default_use_ipcookies) {
      ipcookie_entry_clear_disable_cookies(ce);
      ipcookie_entry_set_expecting_setcookie(ce);
      ipcookie_entry_set_lifetime_log2(ce, 0);
      ipcookie_set_stateless(&((ipcookie_full_state_t *)ipck)->state, &ce->ipcookie, peer);
    } else {
      ipcookie_entry_set_disable_cookies(ce);
      ipcookie_entry_clear_expecting_setcookie(ce);
      ipcookie_entry_set_lifetime_log2(ce, IPCOOKIE_LIFETIME_LOG2_INFINITE);
      memset(ce->ipcookie, 0, sizeof(ce->ipcookie));
    }
    ipcookie_entry_update_mtime(ce);
  }
  return ce;
}

int ipcookies_shim_outbound_cookie(void *ipck, int default_use_ipcookies, struct in6_addr *peer, void **ret_cookie) {
  ipcookie_entry_t *ce = ipcookie_cache_entry_find_by_address(&((ipcookie_full_state_t *)ipck)->cache, peer);
  if (ce) {
    ipcookies_shim_outbound_ipcookie_entry_exists(ce, peer, ret_cookie);
  } else {
    ce = ipcookies_shim_outbound_no_ipcookie_entry(ipck, default_use_ipcookies, peer, ret_cookie);
  }
  if (ce) {
    if(ipcookie_entry_isset_disable_cookies(ce)) {
      return 0;
    } else {
      *ret_cookie = ce->ipcookie;
      return 1;
    }
  } else {
    return 0;
  }
}

int ipcookies_shim_inbound_check_cookie(void *ipck, struct in6_addr *peer, void *cookie) {
  ipcookie_t requested_cookie;
  int res = ipcookie_verify_stateless(&((ipcookie_full_state_t *)ipck)->state, cookie, peer);

  if (res < IPCOOKIE_MATCH_CURR) {
    /* Either no match or the match on prev cookie, build and send SET-COOKIE */
    ipcookie_set_stateless(&((ipcookie_full_state_t *)ipck)->state, &requested_cookie, peer);
    ipcookies_icmp_send(ICMP6_IC_SET_COOKIE, cookie, &requested_cookie, peer);
  }
  return res;
}

#ifndef SHIM_IPCOOKIE_LIBRARY

int main(int argc, char *argv[]) {
  return 0;
}

#endif



