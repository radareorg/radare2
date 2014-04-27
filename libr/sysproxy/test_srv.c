#include <stdio.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>

#define SRV_PORT 8181

/* test with getsockname() shellcode */

extern void process_syscall();

void init_srv_sp()
{
	struct sockaddr_in	in, l;
	int			srv;
	int			con;
	int			len;
	int			opt;
	int t;

	memset(&in, 0, sizeof(in));	
	in.sin_port = htons(SRV_PORT);  
	in.sin_family = AF_INET;

	srv = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(srv < 0) {
		perror("socket");
		exit(1);
	}

	opt = 1;
	if(setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		perror("setsockopt");
		exit(1);
	}


	len = sizeof(in);
	if(bind(srv, (struct sockaddr *)&in, sizeof(in)) < 0) {
		perror("bind");
		exit(1);
	}

	listen(srv, 5);
	while((con = accept(srv, (struct sockaddr *)&in,
			&len)) > 0) {
		int pid;

		pid = fork();
		if(pid == 0) {
			close(srv);
			printf("con: %i\n", con);
			process_syscall();
		} else {
			close(con);	
		}
	}
}

int main(int argc, char **argv)
{
	printf("Esperant conexions rpc al port 8181\n");
	init_srv_sp();
	return 0;
}
