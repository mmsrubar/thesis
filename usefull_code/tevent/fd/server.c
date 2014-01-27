/*
 * ECHO SERVER
 * ===========
 * Simple stream client-server which uses UNIX domain sockets for IPC and tevent
 * lib for watching socket on writing.
 *
 * Server waits for clients and when a client connect than return everything
 * that client send to the server.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <tevent.h>

#define SOCK_PATH "echo.sock"

void handler(	struct tevent_context *ev,
							struct tevent_fd *fde,
							uint16_t flags,
							void *private_data)
{
	int new_fd;
	char str[100];
	struct sockaddr_un remote;
	int t = sizeof(remote);
	int n;
	int done = 0;

	if ((new_fd = accept(*(int *)private_data, (struct sockaddr *)&remote, &t)) == -1) {
		perror("accept");
		exit(1);
	}

	printf("srv> client connected.\n");

	// echo
	do {
		n = recv(new_fd, str, 100, 0);

		if (n <= 0) {
			if (n < 0) perror("recv");
			done = 1;
		}

		if (!done) 
			if (send(new_fd, str, n, 0) < 0) {
				perror("send");
				done = 1;
			}
	} while (!done);

	close(new_fd);
}

int main(void)
{
		// create a new talloc context
		TALLOC_CTX *mem_ctx = NULL;	
		mem_ctx = talloc_new(NULL);

		// create and init a new tevent context
		struct tevent_context *ev_ctx = NULL;
		ev_ctx = tevent_context_init(mem_ctx);

    int s, s2, t, len;
    struct sockaddr_un local, remote;
    char str[100];

		// create UNIX domain socket
    if ((s = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

		// bind socket to a socket file
    local.sun_family = AF_UNIX;					// specify the type
    strcpy(local.sun_path, SOCK_PATH);	// sock name
    unlink(local.sun_path);							// remove socket if it already exists
    len = strlen(local.sun_path) + sizeof(local.sun_family);
    if (bind(s, (struct sockaddr *)&local, len) == -1) {
        perror("bind");
        exit(1);
    }

    if (listen(s, 5) == -1) {
        perror("listen");
        exit(1);
    }

		// add event that will monitor socket and trigger handler func on writing
		struct tevent_fd *fd_event = NULL;
		fd_event = tevent_add_fd(ev_ctx, mem_ctx, s, TEVENT_FD_READ, handler, &s);
		if (fd_event == NULL) {
			printf("error on tevent_add_fd");
			return 0;
		}

		printf("Waiting for a connection...\n");
		tevent_loop_wait(ev_ctx);		// loop forever
}
