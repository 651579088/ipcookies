/********************************************************************

The stateless portion of the cookies, dealing with their generation
and verification.

********************************************************************/

typedef struct ipcookie_state {
  /* time biasing to avoid the synchronization between different instances */
  uint32_t time_bias;
  uint8_t halflife_log2; /* Cookie's lifetime is 2*2^halflife_log2 seconds, 4 bit field */
  uint8_t ipcookie_secret[63]; /* the secret data for ipcookie creation */
} ipcookie_state_t;

/********************************************************************

We have two overlapping windows of time for cookie validity:


   |------------- 2*2^halflife_log2 -------------|
   |
   |                      |------------- 2*2^halflife_log2 -------------|
   |                      |
   |                      |
   ^- timestamp_prev      ^- timestamp_curr  ^--now

The moment the timestamp_prev's validity window ends, timestamp_prev
gets the value of timestamp_curr, and the timestamp_curr gets
the value of now.

Both timestamp_prev and timestamp_curr are conceptual variables,
we calculate them from "now" formulaically the moment we need to
calculate the cookie.

In order to generate the current and previous cookies, the corresponding
dataplane function takes the timestamp_curr or timestamp_prev, mixes in
the peer address and the secret_len of ipcookie_secret, and passes it
to the strong hash function.

Then the resulting cookie is the 96 lowest significant bits of that
hash value:

********************************************************************/

typedef uint8_t ipcookie_t[12];



/*
 *  ipcookie_verify_stateless returns:
 *     IPCOOKIE_NOMATCH: not matched
 *     IPCOOKIE_MATCH_PREV: matched the previous cookie
 *     IPCOOKIE_MATCH_CURR: matched the current cookie
 */

typedef enum {
  IPCOOKIE_NOMATCH = 0,
  IPCOOKIE_MATCH_PREV,
  IPCOOKIE_MATCH_CURR
} ipcookie_match_enum_t;

ipcookie_match_enum_t ipcookie_verify_stateless(ipcookie_state_t *state, ipcookie_t *test_cookie, struct in6_addr *src);

void ipcookie_set_stateless(ipcookie_state_t *state, ipcookie_t *target_cookie, struct in6_addr *peer);
