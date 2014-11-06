all: cookied shim_ipcookies

cookied: cookied.c ipcookies.c

shim_ipcookies: shim_ipcookies.c ipcookies.c

.PHONY: clean
clean:
	rm -f cookied
	rm -f shim_ipcookies
	
