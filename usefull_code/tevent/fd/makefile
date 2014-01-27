CC=gcc
CFLAGS=-std=c99  -g -ltalloc -ltevent

all: server client

server: server.c
	$(CC) $(CFLAGS) $< -o $@

client: client.c
	$(CC) $(CFLAGS) $< -o $@


clean:
	rm -rf client server echo.sock
