all: cookied

cookied: cookied.c ipcookies.c

.PHONY: clean
clean:
	rm -f cookied
	
