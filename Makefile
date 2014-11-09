UNAME := $(shell uname)
ifeq ($(UNAME), Linux)
 LDFLAGS=-lrt
endif

IPCOOKIES_OBJS = \
	ipcookies.o \
	ipcookies_stateless.o \
	ipcookies_cache.o

IPCOOKIES_HDRS = \
	ipcookies.h \
	ipcookies_cache.h \
	ipcookies_stateless.h

all: cookied shim_ipcookies

.c.o:
	$(CC) -c $(CFLAGS) $<

ipcookies.h: ipcookies_cache.h ipcookies_stateless.h
	touch ipcookies.h

ipcookies.o: ipcookies.h
ipcookies_stateless.o: ipcookies.h
ipcookies_cache.o: ipcookies.h

cookied: cookied.o $(IPCOOKIES_OBJS)
	$(CC) $(CFLAGS) $< $(IPCOOKIES_OBJS) -o $@ $(LDFLAGS)

shim_ipcookies: shim_ipcookies.o $(IPCOOKIES_OBJS) $(IPCOOKIES_HDRS) shim_ipcookies.h
	$(CC) $(CFLAGS) $< $(IPCOOKIES_OBJS) -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f cookied
	rm -f shim_ipcookies
	rm -f *.o
