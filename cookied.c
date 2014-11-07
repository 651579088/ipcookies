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

ipcookie_full_state_t *ipck = NULL;


void process_icmp_set_cookie(void *buf, struct sockaddr_in6 icmp_src_addr) {
  struct icmp6_hdr *icmp = (void *)buf;
  struct icmp6_ipcookies *icmp_ipck = (void *)(icmp+1);
  ipcookie_entry_t *ce = ipcookie_find_by_address(ipck, &icmp_src_addr.sin6_addr);
  if(ce) {
    if(!memcmp(ce->ipcookie, icmp_ipck->echoed_cookie, sizeof(ce->ipcookie))) {
      /* The echoed cookie has matched. We can update the entry. */
      memcpy(ce->ipcookie, icmp_ipck->requested_cookie, sizeof(ce->ipcookie));
      ipcookie_entry_update_mtime(ce);
      ipcookie_entry_set_lifetime_log2(ce, icmp->icmp6_ipck_lt_log2 & ICMP6_IPCK_LT_LOG2_MASK);
    } else {
      /* 
       * The echoed cookie has not matched. Either it is a rollover time 
       * and this is the second SET-COOKIE in the train and we already updated,
       * or someone is trying to spoof the SET-COOKIE. Silently ignore.
       */
    }
  } else {
    /* Could not find cookie entry, so need to send back SETCOOKIE-NOT-EXPECTED */
    memcpy(icmp_ipck->echoed_cookie, icmp_ipck->requested_cookie, sizeof(icmp_ipck->echoed_cookie));
    memset(icmp_ipck->requested_cookie, 0, sizeof(icmp_ipck->requested_cookie));
    icmp->icmp6_code = ICMP6_IC_SETCOOKIE_NOT_EXPECTED;
    ipcookies_icmp_send(buf, &icmp_src_addr.sin6_addr);
  }
}

void process_icmp_setcookie_not_expected(void *buf, struct sockaddr_in6 icmp_src_addr) {
  struct icmp6_hdr *icmp = (void *)buf;
  struct icmp6_ipcookies *icmp_ipck = (void *)(icmp+1);
  int cookie_ok = ipcookie_verify_stateless(icmp_ipck->echoed_cookie, &icmp_src_addr.sin6_addr);
  if (cookie_ok) {
    printf("cookied: received a valid setcookie_not_expected");
    if (AF_INET6 == icmp_src_addr.sin6_family) {
        char src[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &icmp_src_addr.sin6_addr, src, INET6_ADDRSTRLEN);
        printf(" from %s\n", src);
    }
    printf(".\n");
  }
}

void receive_icmp(int icmp_sock) {
  uint8_t buf[IPCOOKIES_PACKET_BUF_SIZE];
  struct icmp6_hdr *icmp = (void *)buf;
  struct icmp6_ipcookies *icmp_ipck = (void *)(icmp+1);

  struct sockaddr_in6 icmp_src_addr;
  socklen_t sockaddr_sz = sizeof(struct sockaddr_in6);
  int nread;

  nread = recvfrom(icmp_sock, buf, sizeof(buf), 0,
            (struct sockaddr *)&icmp_src_addr, &sockaddr_sz);
  if (nread == IPCOOKIES_ICMP_SIZE) {
    if(ICMP6_IPCOOKIES == icmp->icmp6_type) {
      switch(icmp->icmp6_code) {
        case ICMP6_IC_SET_COOKIE:
          process_icmp_set_cookie(buf, icmp_src_addr);
          break;
	case ICMP6_IC_SETCOOKIE_NOT_EXPECTED:
          process_icmp_setcookie_not_expected(buf, icmp_src_addr);
          break;
      }
    }
  }
}


int main(int argc, char *argv[]) {
  int icmp_sock = -1;

  icmp_sock = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
  if (icmp_sock == -1) {
    die_perror("icmp socket");
  }

  ipck = mmap_ipcookies();
  
  memset(ipck, 0, sizeof(*ipck));
  while(1) {
    receive_icmp(icmp_sock);
  }
}
