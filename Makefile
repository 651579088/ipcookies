UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
 LDFLAGS=-lrt
endif

all: cookied shim_ipcookies

cookied: cookied.c ipcookies.c ipcookies_stateless.c
	$(CC) $(CFLAGS) cookied.c ipcookies_stateless.c ipcookies.c -o cookied $(LDFLAGS)

shim_ipcookies: shim_ipcookies.c ipcookies.c ipcookies_stateless.c
	$(CC) $(CFLAGS) shim_ipcookies.c ipcookies_stateless.c ipcookies.c -o shim_ipcookies $(LDFLAGS)

.PHONY: clean
clean:
	rm -f cookied
	rm -f shim_ipcookies
