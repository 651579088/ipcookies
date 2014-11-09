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

void die_perror(char *msg) {
  perror(msg);
  exit(1);
}

void ipcookies_icmp_send(uint8_t code, ipcookie_t *echoed_cookie,
                         ipcookie_t *requested_cookie, struct in6_addr *icmp_dst_addr) {
  static int icmp_sock = -1;
  struct sockaddr_in6 sa_dst;
  uint8_t buf[IPCOOKIES_ICMP_SIZE];
  struct icmp6_hdr *icmp = (void *)buf;
  struct icmp6_ipcookies *icmp_ipck = (void *)(icmp+1);
  ipcookie_t zero_cookie = { 0 };

  if (icmp_sock < 0) {
    icmp_sock = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  }
  if (icmp_sock > 0) {
    /* FIXME: recalculate the checksum here */
    icmp->icmp6_type = ICMP6_IPCOOKIES;
    icmp->icmp6_code = code;
    memcpy(icmp_ipck->echoed_cookie, echoed_cookie ? echoed_cookie : &zero_cookie, sizeof(icmp_ipck->echoed_cookie));
    memcpy(icmp_ipck->requested_cookie, requested_cookie ? requested_cookie : &zero_cookie, sizeof(icmp_ipck->requested_cookie));

    sa_dst.sin6_family = AF_INET6;
    sa_dst.sin6_addr = *icmp_dst_addr;
    sendto(icmp_sock, buf, IPCOOKIES_ICMP_SIZE, 0, (struct sockaddr *)&sa_dst, sizeof(sa_dst));
  }
}

/*
 * It's rather ugly to have them here but for now a separate header file
 * just to hide the flags would confuse more than help.
 */

#define IPCOOKIE_ENTRY_MASK_LIFETIME_LOG2       0x0F
#define IPCOOKIE_ENTRY_FLAG_DISABLE_COOKIES     0x10
#define IPCOOKIE_ENTRY_FLAG_EXPECTING_SETCOOKIE 0x20
#define IPCOOKIE_ENTRY_FLAG_RESERVED1           0x40
#define IPCOOKIE_ENTRY_FLAG_RESERVED2           0x80

void ipcookie_entry_set_disable_cookies(ipcookie_entry_t *ce) {
  ce->flags_and_lifetime_log2 |= IPCOOKIE_ENTRY_FLAG_DISABLE_COOKIES;
}

void ipcookie_entry_clear_disable_cookies(ipcookie_entry_t *ce) {
  ce->flags_and_lifetime_log2 &= ~IPCOOKIE_ENTRY_FLAG_DISABLE_COOKIES;
}

int ipcookie_entry_isset_disable_cookies(ipcookie_entry_t *ce) {
  return (ce->flags_and_lifetime_log2 & IPCOOKIE_ENTRY_FLAG_DISABLE_COOKIES);
}

void ipcookie_entry_set_expecting_setcookie(ipcookie_entry_t *ce) {
  ce->flags_and_lifetime_log2 |= IPCOOKIE_ENTRY_FLAG_EXPECTING_SETCOOKIE;
}

void ipcookie_entry_clear_expecting_setcookie(ipcookie_entry_t *ce) {
  ce->flags_and_lifetime_log2 &= ~IPCOOKIE_ENTRY_FLAG_EXPECTING_SETCOOKIE;
}

int ipcookie_entry_isset_expecting_setcookie(ipcookie_entry_t *ce) {
  return(ce->flags_and_lifetime_log2 & IPCOOKIE_ENTRY_FLAG_EXPECTING_SETCOOKIE);
}

uint8_t ipcookie_entry_get_lifetime_log2(ipcookie_entry_t *ce) {
  return (ce->flags_and_lifetime_log2 & IPCOOKIE_ENTRY_MASK_LIFETIME_LOG2);
}

void ipcookie_entry_set_mtime(ipcookie_entry_t *ce, time_t now) {
  ce->mtime_lo16 = 0xffff & now;
  ce->mtime_hi8 = 0xff & (now >> 16);
}

void ipcookie_entry_update_mtime(ipcookie_entry_t *ce) {
  time_t now = time(NULL);
  ipcookie_entry_set_mtime(ce, now);
}

/* Expand the timestamp from the low 24 bits */
time_t expand_timestamp(time_t now, uint8_t hi8, uint16_t lo16) {
  time_t now_lo24 = now & 0xFFFFFF;
  time_t ts_zero_lo24 = now ^ now_lo24;
  time_t ts_lo24 = lo16 | (hi8 << 16);
  if (now_lo24 < ts_lo24) {
    /* the overflow has occured in the meantime, normalize. */
    ts_zero_lo24 -= 0x1000000;
  }
  return (ts_zero_lo24 | ts_lo24);
}

ipcookie_ts_check_t check_ipcookie_entry_timestamp(ipcookie_entry_t *ce) {
  time_t now = time(NULL);
  time_t ts = expand_timestamp(now, ce->mtime_hi8, ce->mtime_lo16);
  time_t lifetime = (1 << ipcookie_entry_get_lifetime_log2(ce));

  if ((now < ts + lifetime) || (1<<IPCOOKIE_LIFETIME_LOG2_INFINITE == lifetime)) {
    return IPCOOKIE_TS_STILL_VALID;
  } else if (now < ts + lifetime + IPCOOKIE_T_RECOVER) {
    return IPCOOKIE_TS_RENEW_TIME;
  } else {
    return IPCOOKIE_TS_PAST_RENEW_TIME;
  }
}

void ipcookie_entry_set_lifetime_log2(ipcookie_entry_t *ce, int new_lifetime_log2) {
  if( (new_lifetime_log2 < 256) && (new_lifetime_log2 >= 0) ) {
    ce->flags_and_lifetime_log2 &= ~IPCOOKIE_ENTRY_MASK_LIFETIME_LOG2;
    ce->flags_and_lifetime_log2 |= (new_lifetime_log2 & IPCOOKIE_ENTRY_MASK_LIFETIME_LOG2);
  }
}

void ipcookie_entry_mtime_backdate_by_lifetime_log2(ipcookie_entry_t *ce) {
  time_t backdated_now = time(NULL) - (1 << ipcookie_entry_get_lifetime_log2(ce));
  ipcookie_entry_set_mtime(ce, backdated_now);
}



ipcookie_full_state_t *mmap_ipcookies(void) {
  int fd;
  ipcookie_full_state_t *ipck = NULL;

  fd = shm_open("/ipcookies", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    die_perror("ipcookies shm_open");
  }
  if (ftruncate(fd, sizeof(ipcookie_full_state_t)) == -1) {
    // die_perror("ipcookies ftruncate");
    perror("ipcookies ftruncate");
  }
  ipck = mmap(NULL, sizeof(*ipck),
       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (ipck == MAP_FAILED) {
    die_perror("ipcookies mmap");
  }
  close(fd);
  return ipck;
}
