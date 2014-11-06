/********************************************************************

This implements the conceptual IP cookie algorithm in a verbatim
and naive way to ensure the simplicity and provide a reference
implementation.

The aim of this algorithm is to eventually mitigate the source-spoofing 
amplification attacks related to protocols which trust the source 
address of the datagram.

It consists of two parts: a cookie daemon and the shim.

Cookie daemon maintains two structures in memory shared with the shim's 
instances:

ipcookie_state_t ipcookie_state;
ipcookie_cache_t ipcookie_cache;

The first one maintains the cookie-related state for the host
for the stateless "server" portion of the cookies:

********************************************************************/

typedef struct ipcookie_state {
  time_t timestamp_prev; /* when was the previous ipcookie generation */
  time_t timestamp_curr; /* when was the current ipcookie generation */
  uint8_t halflife_log2; /* Cookie's lifetime is 2*2^halflife_log2 seconds, 4 bit field */
  char ipcookie_secret[63]; /* the secret data for ipcookie creation */
} ipcookie_state_t;

/********************************************************************

In order to generate the current and previous cookies, the corresponding
dataplane function takes the timestamp_curr or timestamp_prev, mixes in
the peer address and the secret_len of ipcookie_secret, and passes it
to the strong hash function.

Then the resulting cookie is the 96 lowest significant bits of that 
hash value:

********************************************************************/

typedef uint8_t ipcookie_t[12];


/********************************************************************

The second data structure is the cookie state maintained for the peers
requesting the cookie use, as well as a scratchpad to keep track 
the explicit non-usage of the cookies for specific peers as both 
client and server in order to perform the fallback (the remote side
supports the cookies, but the required messages do not pass.

The entries in this table are created when the local side is the initiator
of the communication.

They are being used to fill in the cookie value in outgoing packets,
and also to allow the verification of the control messages.

********************************************************************/

typedef struct ipcookie_entry {
  struct in6_addr peer;    /* Which peer this is for */
  uint16_t mtime_lo16;     /* Low bits of timestamp when this entry was 
                              last modified (aka when we saw the previous SET-COOKIE) */
  uint8_t flags;           /* Flags of this entry */
  uint8_t  lifetime_log2;  /* 4 bits field. Log2 of the expected lifetime.
			      We should see a SET-COOKIE within mtime + 2^lifetime_log2 seconds */
  ipcookie_t ipcookie;     /* The ipcookie itself */
} ipcookie_entry_t;

/********************************************************************

With a table of 64K, the total size of the data structure is
32*65536 = 2Mbytes, which is well within the size of the L2 cache
of a lot of the modern CPUs, so even though the linear array
is not a very efficient way to store and retrieve the data,
it should be prefetch-friendly thus may give a usable performance 
from the get-go. Under this assumption, we leave the optimizations
to another, more sophisticated implementation.

********************************************************************/


typedef struct ipcookie_cache_struct {
  uint16_t entry_count; 
  uint8_t padding[14];
  struct ipcookie_entry entries[65536];
} ipcookie_cache_t; 



typedef struct ipcookie_full_state {
  ipcookie_state_t state;
  ipcookie_cache_t cache;
} ipcookie_full_state_t;



/********************************************************************

Therea are two ICMP messages in the protocol: SET-COOKIE and 
SETCOOKIE-NOT-EXPECTED.

Cookie daemon's job is relatively simple: listen to the received 
ICMP messages, verify them against the existing cookie,
and if this verification process passes, update the cookie 
values into the table. 

The first one is the message to set/correct the cookie, sent by a responder
peer.

If we receive SET-COOKIE and the cookie entry for the peer is not present,
we copy the sender's cookie into an SETCOOKIE-NOT-EXPECTED message and
reply with that message back to the sender.

If we receive SET-COOKIE and the cookie entry for the peer exists,
we verify that echoed cookie in this message matches the entry, 
and then use the suggested cookie to update the table.
We also update the lifetime_log2 from the received packet.
This will allow us to (somewhat) detect the blackholes which
can arise later if the network topology changes.

If we receive SETCOOKIE-NOT-EXPECTED, we verify its cookie
using the stateless cookie creation algorithm for that peer, if there
is a match, this means it is a valid reaction to the SET-COOKIE
which we sent, this means the original data packet triggering SET-COOKIE
was spoofed. This is a loggable event.

If we receive SETCOOKIE-NOT-EXPECTED and the stateless cookie verification
fails, this means this notification has been spoofed and it MUST be
ignored, possibly with rate-limited logging.

********************************************************************/


/********************************************************************

The shim's job is two fold:

On the receive path: 

It needs to verify the incoming packets 
which contain the cookie destination option against the stateless
server CURRENT cookie, and if that fails, attempt to verify against
server PREVIOUS cookie.

If the verification against CURRENT cookie fails,
the shim needs to send the SET-COOKIE message containing the 
value of the calculated CURRENT cookie, and a copy of the received
cookie in the echo-cookie field. The packet needs to also contain
a copy of the halflife_log2 field to inform the remote side on when
to expect an update of the cookie. No new state is created.

If the received cookie verifies against either the CURRENT or
PREVIOUS calculated cookies, then the received datagram can be passed
further to the host stack.

On the send path:

It needs to look up the cookie cache if an entry for a given peer
exists. If it exists, we act according to following:

ENTRY EXISTS {
We need to check the whether the
(mtime_ts + 2^lifetime_log2) in that entry is already less than
the current timestamp.

If it is, we look if the flag DISABLE_COOKIES is set.

If it is not, this means we haven't heard the SET-COOKIE 
packet when we should have - so either the upstream
packet with cookie or the return SET-COOKIE has been dropped. We need to 
set the DISABLE_COOKIES, set the mtime_ts to the current timestamp, and 
set the lifetime_log2 to a host-specific value which will determine when
we try to reenable the cookies again for that peer.

if the flag DISABLE_COOKIES is set, this means that the wait-out time has expired,
and we can try to send the cookies again. We clear the flag, set the mtime_ts to current
timestamp, and lifetime_log2 to zero (the assumption is that we can get the SET-COOKIE
within a second, thus if an RTT is high, this value of zero would need to be changed on
some basis. How this is done is TBD).

}

If the entry does not exist:

ENTRY DOES NOT EXIST {
  we need to allocate a new entry for this peer, using FIFO or some other
  queue management algorithm to evict the old entries. 

  The new entry gets DISABLE_COOKIES flag set or cleared depending on the local policy,
  the mtime_ts is set to the current timestamp, and lifetime_log2 is set to the value of zero 
  (or other administratively defined value).

}

The next thing we do is make a decision whether to add the cookie option 
to the packet, or to send it as is. For this we will look at 
the DISABLE_COOKIES flag. In this conceptual implementation we present this
as two separate lookups with the above, to modularize it. A more optimized 
implementation is certainly possible, but is not a focus at this time.

If the flag DISABLE_COOKIES is set, then the packet needs to be sent as-is,
with no cookie attached.

If the flag DISABLE_COOKIES is not set, then we need to take the cookie
value from the entry and insert it as a destination option.

********************************************************************/
