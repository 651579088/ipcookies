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
	ipcookie_entry_set_expecting_setcookie(ce);
	break;
      case IPCOOKIE_TS_PAST_RENEW_TIME:
        ipcookie_entry_past_renew_with_cookie(ce, peer, ret_cookie);
	break;
    }
  }
}

ipcookie_entry_t *ipcookies_shim_outbound_no_ipcookie_entry(void *ipck, int default_use_ipcookies, struct in6_addr *peer, void **ret_cookie) {
  ipcookie_entry_t *ce = ipcookie_entry_allocate(ipck);
  if (ce) {
    if (default_use_ipcookies) {
      ipcookie_entry_clear_disable_cookies(ce);
      ipcookie_entry_set_expecting_setcookie(ce);
      ipcookie_entry_set_lifetime_log2(ce, 0);
      ipcookie_set_stateless(&ce->ipcookie, peer);
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
  ipcookie_entry_t *ce = ipcookie_find_by_address(ipck, peer);
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



