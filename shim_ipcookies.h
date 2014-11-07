#include <netinet/in.h>

/*********************************************************************

This is an implementation of the shim layer.

On the sending path, the function ipcookies_shim_outbound_cookie returns
true if the cookie needs to be added to the packet being sent.
The cookie to set is passed via an output parameter pointer. The function as the side
effect of creating the necessary state within ipck database if needed.

The parameter default_use_ipcookies defines what to do if the cookie
does not already exist.

The sender has to take care to add the cookie via the mechanism of choice.

*********************************************************************/

int ipcookies_shim_outbound_cookie(void *ipck, int default_use_ipcookies, struct in6_addr *peer, void **ret_cookie);



/*********************************************************************

On the receiving path, the function ipcookies_shim_inbound_check_cookie
returns true if the packet can be passed further to the application, 
or whether it should be dropped. As a side effect this function may send
SET-COOKIE ICMP message to the peer to verify the sender address, and
change the state recorded within ipck database.

If the cookie option was not present in the packet, then the caller
should pass the NULL as a cookie parameter. This allows the routine
to perform a policy check of what to do with such packets.

*********************************************************************/

int ipcookies_shim_inbound_check_cookie(void *ipck, struct in6_addr *peer, void *cookie);


