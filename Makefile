all: cookied shim_ipcookies

cookied: cookied.c ipcookies.c ipcookies_stateless.c

shim_ipcookies: shim_ipcookies.c ipcookies.c ipcookies_stateless.c

.PHONY: clean
clean:
	rm -f cookied
	rm -f shim_ipcookies
	
