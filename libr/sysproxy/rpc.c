#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "sp.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int		rpc_con;
static char		rpc_data[MAX_PACKET];
static char		*remote_buf; 

void dump(char *buf, int len)
{
	int i; 

	printf("dump buf 0x%x with len %i\n", (unsigned int)buf, len);

	for(i = 0; i < len; i++) {
		if(i % 16 == 0)
			printf("\n  %.2x", (unsigned char)buf[i]);
		else
			printf(" %.2x", (unsigned char )buf[i]);
	}
	printf("\n");
}

int dump_raw(char *buf, int len)
{	
	int i;
	for(i = 0;i < len; i++)
		printf("%c", buf[i]);
	exit(1);
}

inline char *rpc_data_at(int off)
{
	return rpc_data + sizeof(struct regs) + off;
}

int rpc_syscall(struct regs *rg,
		 struct arg **args, int n_args)
{
	char		*p;
	int		i;
	int		ret;
	
	/* copy arguments */
	p  = (char *)(rpc_data + sizeof(*rg));

	for(i = 0; i < n_args; p += args[i]->len, i++) {
		if(p + args[i]->len > rpc_data + MAX_PACKET) {
			errno = ENOMEM;
			return -1;
		}

		memcpy(p, args[i]->buf, args[i]->len);
	}

	/* copy registers */
	memcpy(rpc_data, rg, sizeof(*rg));

#ifdef DEBUG 
	dump(rpc_data, (unsigned long)p - (unsigned long)rpc_data);
#endif
	//dump_raw(rpc_data,(unsigned long)p - (unsigned long)rpc_data);

	/* send rpc */
	ret = write(rpc_con, rpc_data,
		(unsigned long)p - (unsigned long)rpc_data);
		

	/* error? */
	if(ret < 0)
		return ret;

	/* wait for response ... */
	ret = read(rpc_con, rpc_data, MAX_PACKET);
	if(ret < 0)
		return ret;

	rg = (struct regs *)rpc_data;

	return rg->eax;
}

inline unsigned long rpc_reloc(int off)
{
	return (unsigned long)(remote_buf + off);
}

void rpc_init(char *host, int port)
{
	struct sockaddr_in	in;
	int			ret;

	memset(&in, 0, sizeof(in));
	in.sin_addr.s_addr = inet_addr(host);
	in.sin_port = htons(port);
	in.sin_family = AF_INET;

	rpc_con = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(rpc_con < 0) {
		perror("socket");
		exit(1);
	}

	if(connect(rpc_con, (struct sockaddr *)&in, sizeof(in)) < 0) {
		perror("rpc_connect");
		exit(1);
	}

	ret = read(rpc_con, &remote_buf, sizeof(char *));
	
	if(ret < 0) {
		perror("read");
		exit(1);
	} else {
		printf("ret: %i\n", ret);
		if(ret != sizeof(char *)) {
			fprintf(stderr, "ERROR: Invalid buffer address!\n");
			//exit(1);
		}
	}

	printf("Remote buf: 0x%x\n", (unsigned int)remote_buf);
}
