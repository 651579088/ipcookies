enum {
  IPCOOKIE_NOMATCH = 0,
  IPCOOKIE_MATCH_PREV,
  IPCOOKIE_MATCH_CURR
} ipcookie_match_enum_t;

/*
 *  ipcookie_verify_stateless returns:
 *     IPCOOKIE_NOMATCH: not matched
 *     IPCOOKIE_MATCH_PREV: matched the previous cookie
 *     IPCOOKIE_MATCH_CURR: matched the current cookie
 */

int ipcookie_verify_stateless(ipcookie_state_t *state, ipcookie_t testcookie, struct in6_addr *src);

void ipcookie_set_stateless(ipcookie_state_t *state, ipcookie_t *target_cookie, struct in6_addr *peer);
