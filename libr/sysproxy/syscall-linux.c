#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "sp.h"

extern unsigned long rpc_reloc(int off);
extern char *rpc_data_at(int off);
extern int rpc_syscall(struct regs *rg,
		 struct arg **args, int n_args);

int sys_write(int fd, char *buf, int len)
{
	struct regs	r;
	struct arg	*args[1];
	struct arg	arg;

	memset(&r, 0, sizeof(r));
	r.eax = 4;
	r.ebx = fd; 
	r.edx = len;
	/* reference first argument */
	r.ecx = rpc_reloc(sizeof(r));

	/* buffer argument */
	arg.len = len;
	arg.buf = buf;
	args[0] = &arg;

	return rpc_syscall(&r, args, 1); 
}

int sys_open(char *f, int flags, int  mode)
{
	struct regs	r;
	struct arg	*args[1];
	struct arg	arg;

	memset(&r, 0, sizeof(r));
	r.eax = 5;
	r.ebx = rpc_reloc(sizeof(r));
	r.edx = mode;
	r.ecx = flags;

	/* buffer argument */
	arg.len = strlen(f) + 1;
	arg.buf = f;
	args[0] = &arg;

	return rpc_syscall(&r, args, 1); 
}

int sys_read(int fd, char *b, int len)
{
	struct regs	r;
	struct arg	*args[1];
	struct arg	arg;
	int		ret;

	memset(&r, 0, sizeof(r));
	r.eax = 3;
	r.ebx = fd;
	r.ecx = rpc_reloc(sizeof(r));
	r.edx = len;

	/* buffer argument */
	arg.len = 0;
	arg.buf = b;
	args[0] = &arg;

	ret = rpc_syscall(&r, args, 1); 
	if(ret > 0)
		memcpy(b, (char *)rpc_data_at(0), ret);

	return ret;
}

int sys_lseek(int af, int f, int proto)
{
	struct regs	r;
	struct arg	*args[1];
	struct arg	arg;
	int		sock_args[3];

	memset(&r, 0, sizeof(r));
	r.eax = 19;
	r.ebx = 1;
	r.ecx = rpc_reloc(sizeof(r));

	sock_args[0] = af;
	sock_args[1] = f;
	sock_args[2] = proto;

	/* buffer argument */
	arg.len = 0;
	arg.buf = NULL;
	args[0] = &arg;

	return rpc_syscall(&r, args, 1); 
}

int sys_socket(int af, int f, int proto)
{
	struct regs	r;
	struct arg	*args[1];
	struct arg	arg;
	int		sock_args[3];

	memset(&r, 0, sizeof(r));
	r.eax = 0x66;
	r.ebx = 1;
	r.ecx = rpc_reloc(sizeof(r));

	sock_args[0] = af;
	sock_args[1] = f;
	sock_args[2] = proto;

	/* buffer argument */
	arg.len = sizeof(sock_args);
	arg.buf = (char *)sock_args;
	args[0] = &arg;

	return rpc_syscall(&r, args, 1); 
}

int sys_bind(int s, char *b, int len)
{
	struct regs	r;
	struct arg	*args[2];
	struct arg	arg[2];
	int		sock_args[3];

	memset(&r, 0, sizeof(r));
	r.eax = 0x66;
	r.ebx = 2;
	r.ecx = rpc_reloc(sizeof(r));

	sock_args[0] = s;
	sock_args[1] = rpc_reloc(sizeof(r) + sizeof(sock_args));
	sock_args[2] = len;

	/* buffer argument */
	arg[0].len = sizeof(sock_args);
	arg[0].buf = (char *)sock_args;
	args[0] = &arg[0];

	/* buffer argument */
	arg[1].len = len;
	arg[1].buf = b;
	args[1] = &arg[1];

	return rpc_syscall(&r, args, 2); 
}

int sys_setsockopt(int s, int l, int optn, char *optval, int optlen)
{
	struct regs	r;
	struct arg	*args[1];
	struct arg	arg[1];
	int		sock_args[5];

	memset(&r, 0, sizeof(r));
	r.eax = 0x66;
	r.ebx = 0xe;
	r.ecx = rpc_reloc(sizeof(r));

	sock_args[0] = s;
	sock_args[1] = l;
	sock_args[2] = optn;
	sock_args[3] = (int)rpc_reloc(sizeof(r) + sizeof(sock_args));
	sock_args[4] = optlen;

	arg[0].len = sizeof(sock_args);
	arg[0].buf = (char *)sock_args;
	args[0] = &arg[0];
				
	arg[1].len = optlen;
	arg[1].buf = optval;
	args[1] = &arg[1];

	return rpc_syscall(&r, args, 2);
}

int sys_listen(int s, int b)
{
	struct regs	r;
	struct arg	*args[1];
	struct arg	arg;
	int		sock_args[2];

	memset(&r, 0, sizeof(r));
	r.eax = 0x66;
	r.ebx = 4;
	r.ecx = rpc_reloc(sizeof(r));

	sock_args[0] = s;
	sock_args[1] = b;

	/* buffer argument */
	arg.len = sizeof(sock_args);
	arg.buf = (char *)sock_args;
	args[0] = &arg;

	return rpc_syscall(&r, args, 1); 
}

int sys_accept(int s, char *b, int *len)
{
	struct regs	r;
	struct arg	*args[3];
	struct arg	arg[3];
	int		sock_args[3];

	memset(&r, 0, sizeof(r));
	r.eax = 0x66;
	r.ebx = 5;
	r.ecx = rpc_reloc(sizeof(r));

	sock_args[0] = s;
	sock_args[1] = rpc_reloc(sizeof(r) + sizeof(sock_args));
	sock_args[2] = rpc_reloc(sizeof(r) + sizeof(sock_args) + *len);

	/* buffer argument */
	arg[0].len = sizeof(sock_args);
	arg[0].buf = (char *)sock_args;
	args[0] = &arg[0];

	/* buffer argument */
	arg[1].len = *len;
	arg[1].buf = b;
	args[1] = &arg[1];

	/* buffer argument */
	arg[2].len = sizeof(*len);
	arg[2].buf = (char *)len;
	args[2] = &arg[2];

	return rpc_syscall(&r, args, 3); 

}

int sys_execve(char *f, char **argv, char **env)
{
	struct regs	r;
	struct arg	**args;
	struct arg	*arg;
	int		n_args = 1;
	int		file_len = strlen(f) + 1;
	char		**args_p = NULL;
	char		**env_p = NULL;
	int		args_len = 0, env_len = 0;
	int		off;
	int		i, ret;

	memset(&r, 0, sizeof(r));
	r.eax = 0xb;

	/* filename */
	r.ebx = rpc_reloc(sizeof(r));

	/* arguments */
	r.ecx = rpc_reloc(sizeof(r) + file_len);

	/* get length of arguments array */
	if(argv)  {
		for(; argv[args_len] != NULL; args_len++)
			;
		/* arguments */
		r.ecx = rpc_reloc(sizeof(r) + file_len);
		args_len++;
	} else {
		/* arguments */
		r.ecx = 0;
	}

	/* get length of environments array */
	if(env) {
		for(; env[env_len] != NULL; env_len++)
			;
		/* environment */
		r.edx = rpc_reloc(sizeof(r) + file_len + sizeof(char *) \
				* args_len);
		env_len++;
	} else {
		/* environment */
		r.edx = 0;
	}

	args = (struct arg **)malloc(sizeof(struct arg *) * \
		(args_len + env_len + 1));	

	if(args == NULL)
		return -ENOMEM;

	arg = (struct arg *)malloc(sizeof(struct arg) * \
		(args_len + env_len + 1));	

	if(arg == NULL)
		goto err_exec;
		
	/* buffer argument */
	arg[0].len = file_len;
	arg[0].buf = f;
	args[0] = &arg[0];

	if(args_len) {
		/* arguments array */
		args_p = (char **)malloc((args_len + 1) * sizeof(char *));
		if(args_p == NULL)
			goto err_exec;

		args_p[args_len] = 0;

		arg[n_args].len = args_len * sizeof(char *);
		arg[n_args].buf = (char *)args_p;
		args[n_args] = &arg[n_args];

		n_args++;
	}

	if(env_len) {
		/* environment array */
		env_p = (char **)malloc((env_len + 1) * sizeof(char *));
		if(env_p == NULL)
			goto err_exec;

		env_p[env_len] = 0;

		arg[n_args].len = env_len * sizeof(char *);
		arg[n_args].buf = (char *)env_p;
		args[n_args] = &arg[n_args];

		n_args++;
	}

	off = sizeof(r) + file_len + (args_len) * sizeof(char *) + \
			(env_len) * sizeof(char *);

	/* arguments */
	for(i = 0; i < args_len - 1; i++, n_args++) {
		arg[n_args].len = strlen(argv[i]) + 1;
		arg[n_args].buf = argv[i];
		args[n_args] = &arg[n_args];
		args_p[i] = (char *)rpc_reloc(off);
		off += arg[n_args].len;
	}

	/* environment */
	for(i = 0; i < env_len - 1; i++, n_args++) {
		arg[n_args].len = strlen(env[i]) + 1;
		arg[n_args].buf = env[i];
		args[n_args] = &arg[n_args];
		env_p[i] = (char *)rpc_reloc(off);
		off += arg[n_args].len;
	}

	ret = rpc_syscall(&r, args, n_args); 

err_exec:

	free(args);
	if(arg)
		free(arg);

	if(env_p)
		free(env_p);

	if(args_p)
		free(args_p);

	return ret;
}

int sys_dup2(int o, int n)
{
	struct regs	r;

	memset(&r, 0, sizeof(r));
	r.eax = 0x3f;
	r.ebx = o; 
	r.ecx = n;

	return rpc_syscall(&r, NULL, 0); 
}

int sys_close(int d)
{
	struct regs	r;

	memset(&r, 0, sizeof(r));
	r.eax = 6;
	r.ebx = d; 

	return rpc_syscall(&r, NULL, 0); 
}
