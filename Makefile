UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
 LDFLAGS=-lrt
endif

all: cookied shim_ipcookies

cookied: cookied.c ipcookies.c
	$(CC) $(CFLAGS) cookied.c ipcookies.c -o cookied $(LDFLAGS)

shim_ipcookies: shim_ipcookies.c ipcookies.c
	$(CC) $(CFLAGS) shim_ipcookies.c ipcookies.c -o shim_ipcookies $(LDFLAGS)

.PHONY: clean
clean:
	rm -f cookied
	rm -f shim_ipcookies
