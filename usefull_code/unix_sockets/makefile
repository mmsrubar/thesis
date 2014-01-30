CC=gcc
CFLAGS=-std=c99  -g

all: server client

server: server.c
	$(CC) $(CFLAGS) $< -o $@

client: client.c
	$(CC) $(CFLAGS) $< -o $@


clean:
	rm -rf client server echo.sock
