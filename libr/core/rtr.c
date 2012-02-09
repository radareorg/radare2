/* radare - Copyright 2009-2012 pancake+nibble */

#include "r_core.h"
#include "r_socket.h"

#define endian core->assembler->big_endian
#define rtr_n core->rtr_n
#define rtr_host core->rtr_host

R_API void r_core_rtr_help(RCore *core) {
	r_cons_printf (
	" =                  ; list all open connections\n"
	" =<[fd] cmd         ; send output of local command to remote fd\n"
	" =[fd] cmd          ; exec cmd at remote 'fd' (last open is default one)\n"
	" =! cmd             ; run command via r_io_system\n"
	" =+ [proto://]host  ; add host (default=rap://, tcp://, udp://)\n"
	" =-[fd]             ; remove all hosts or host 'fd'\n"
	" ==[fd]             ; open remote session with host 'fd', 'q' to quit\n");
}

R_API void r_core_rtr_pushout(RCore *core, const char *input) {
	int fd = atoi (input);
	const char *cmd = NULL;
	char *str = NULL;
	if (fd) {
		for (rtr_n = 0; rtr_host[rtr_n].fd->fd != fd \
			&& rtr_n < RTR_MAX_HOSTS; rtr_n++);
		if (!(cmd = strchr (input, ' '))) {
			eprintf ("Error\n");
			return;
		}
	} else cmd = input;

	if (!rtr_host[rtr_n].fd->fd) {
		eprintf("Error: Unknown host\n");
		return;
	}

	if (!(str = r_core_cmd_str (core, cmd))) {
		eprintf ("Error: radare_cmd_str returned NULL\n");
		return;
	}
	
	switch (rtr_host[rtr_n].proto) {
	case RTR_PROT_RAP:
		eprintf ("Error: Cannot use '=<' to a rap connection.\n");
		break;
	case RTR_PROT_TCP:
	case RTR_PROT_UDP:
	default:
		r_socket_write (rtr_host[rtr_n].fd, str, strlen (str));
		break;
	}
	free (str);
}

R_API void r_core_rtr_list(RCore *core) {
	int i;
	for (i = 0; i < RTR_MAX_HOSTS; i++)
		if (rtr_host[i].fd) {
			r_cons_printf("%i - ", rtr_host[i].fd->fd);
			if (rtr_host[i].proto == RTR_PROT_TCP)
				r_cons_printf("tcp://");
			else if (rtr_host[i].proto == RTR_PROT_UDP)
				r_cons_printf("udp://");
			else r_cons_printf("rap://");
			r_cons_printf ("%s:%i/%s\n", rtr_host[i].host,
				rtr_host[i].port, rtr_host[i].file);
	}
}
		
R_API void r_core_rtr_add(RCore *core, const char *_input) {
	char *port, input[1024], *host = NULL, *file = NULL, *ptr = NULL, buf[1024];
	int proto, i;
	RSocket *fd;

	strncpy (input, _input, sizeof (input)-4);
	/* Parse uri */
	if ((ptr = strstr(input, "tcp://"))) {
		proto = RTR_PROT_TCP;
		host = ptr+6;
	} else if ((ptr = strstr(input, "udp://"))) {
		proto = RTR_PROT_UDP;
		host = ptr+6;
	} else if ((ptr = strstr(input, "rap://"))) {
		proto = RTR_PROT_RAP;
		host = ptr+6;
	} else {
		proto = RTR_PROT_RAP;
		host = input;
	}
	while (*host&&iswhitechar(*host))
		host++;

	if (!(ptr = strchr (host, ':'))) {
		eprintf ("Error: Port is not specified\n");
		return;
	}
	ptr[0] = '\0';
	ptr = ptr+1;

	if (!(file = strchr (ptr, '/'))) {
		eprintf("Error: Missing '/'\n");
		return;
	}
	file[0] = '\0';
	file = file+1;
	port = ptr;

	fd = r_socket_new (R_FALSE);
	if (!fd) {
		eprintf ("Error: Cannot create new socket\n");
		return;
	}
	switch (proto) {
	case RTR_PROT_RAP:
		if (!r_socket_connect_tcp (fd, host, port)) { //TODO: Use rap.ssl
			eprintf ("Error: Cannot connect to '%s' (%s)\n", host, port);
			return;
		}
		eprintf ("Connected to: %s at port %s\n", host, port);
		/* send */
		buf[0] = RTR_RAP_OPEN;
		buf[1] = 0;
		buf[2] = (ut8)(strlen (file)+1);
		memcpy (buf+3, file, buf[2]);
		r_socket_write(fd, buf, 3+buf[2]);
		/* read */
		eprintf ("waiting... "); fflush(stdout);
		r_socket_read (fd, (ut8*)buf, 5);
		r_mem_copyendian ((ut8 *)&i, (ut8*)buf+1, 4, core->assembler->big_endian);
		if (buf[0] != (char)(RTR_RAP_OPEN|RTR_RAP_REPLY) || i<= 0) {
			eprintf ("Error: Wrong reply\n");
			return;
		}
		eprintf ("ok\n");
		break;
	case RTR_PROT_TCP:
		if (!r_socket_connect_tcp (fd, host, port)) { //TODO: Use rap.ssl
			eprintf("Error: Cannot connect to '%s' (%s)\n", host, port);
			return;
		}
		eprintf ("Connected to: %s at port %s\n", host, port);
		break;
	case RTR_PROT_UDP:
		if (!r_socket_connect_udp(fd, host, port)) { //TODO: Use rap.ssl
			eprintf("Error: Cannot connect to '%s' (%s)\n", host, port);
			return;
		}
		eprintf("Connected to: %s at port %s\n", host, port);
		break;
	}

	for (i = 0; i < RTR_MAX_HOSTS; i++)
		if (!rtr_host[i].fd) {
			rtr_host[i].proto = proto;
			memcpy (rtr_host[i].host, host, 512);
			rtr_host[i].port = atoi(port);
			memcpy (rtr_host[i].file, file, 1024);
			rtr_host[i].fd = fd;
			rtr_n = i;
			break;
		}

	r_core_rtr_list (core);
}

R_API void r_core_rtr_remove(RCore *core, const char *input) {
	int fd, i;

	if (input[0] >= '0' && input[0] <= '9') {
		fd = r_num_math (core->num, input);
		for (i = 0; i < RTR_MAX_HOSTS; i++)
			if (rtr_host[i].fd->fd == fd) {
				r_socket_free (rtr_host[i].fd);
				rtr_host[i].fd = NULL;
				if (rtr_n == i)
					for (rtr_n = 0; !rtr_host[rtr_n].fd && rtr_n < RTR_MAX_HOSTS; rtr_n++);
				break;
		}
	} else {
		for (i = 0; i < RTR_MAX_HOSTS; i++)
			if (rtr_host[i].fd)
				r_socket_free (rtr_host[i].fd);
		memset (rtr_host, '\0', RTR_MAX_HOSTS * sizeof(RCoreRtrHost));
		rtr_n = 0;
	}
}

R_API void r_core_rtr_session(RCore *core, const char *input) {
	char prompt[32], buf[4096];
	int fd;

	if (input[0] >= '0' && input[0] <= '9') {
		fd = r_num_math (core->num, input);
		//for (rtr_n = 0; rtr_host[rtr_n].fd->fd != fd && rtr_n < RTR_MAX_HOSTS; rtr_n++);
	}

	for (;;) {
		if (rtr_host[rtr_n].fd)
			snprintf (prompt, sizeof (prompt),
				"fd:%d> ", rtr_host[rtr_n].fd->fd);
		r_line_singleton ()->prompt = prompt;
		if ((r_cons_fgets (buf, sizeof (buf), 0, NULL))) {
			if (*buf == 'q')
				break;
			else if (*buf == 'V') {
				eprintf ("Visual mode not supported\n");
				continue;
			}
			r_core_rtr_cmd (core, buf);
			r_cons_flush ();
		}
	}
}

R_API void r_core_rtr_cmd(RCore *core, const char *input) {
	char bufw[1024], bufr[8];
	const char *cmd = NULL, *cmd_output = NULL;
	int i, cmd_len, fd = atoi (input);

	if (fd != 0) {
		if (rtr_host[rtr_n].fd)
			for (rtr_n = 0; rtr_host[rtr_n].fd->fd != fd
				&& rtr_n < RTR_MAX_HOSTS; rtr_n++);
		if (!(cmd = strchr (input, ' '))) {
			eprintf ("Error\n");
			return;
		}
	} else cmd = input;

	if (!rtr_host[rtr_n].fd){
		eprintf ("Error: Unknown host\n");
		return;
	}

	if (!rtr_host[rtr_n].proto == RTR_PROT_RAP){
		eprintf ("Error: Not a rap:// host\n");
		return;
	}

	/* send */
	bufw[0] = RTR_RAP_CMD;
	i = strlen (cmd) + 1;
	r_mem_copyendian ((ut8*)bufw+1, (ut8*)&i, 4, endian);
	memcpy (bufw+5, cmd, i);
	r_socket_write (rtr_host[rtr_n].fd, bufw, 5+i);
	/* read */
	r_socket_read (rtr_host[rtr_n].fd, (ut8*)bufr, 5);
	if (bufr[0] != (char)(RTR_RAP_CMD|RTR_RAP_REPLY)) {
		eprintf ("Error: Wrong reply\n");
		return;
	}
	r_mem_copyendian ((ut8*)&cmd_len, (ut8*)bufr+1, 4, endian);
	if (i == 0)
		return;
	if (i < 0) {
		eprintf ("Error: cmd length < 0\n");
		return;
	}
	cmd_output = malloc (cmd_len);
	if (!cmd_output) {
		eprintf ("Error: Allocating cmd output\n");
		return;
	}
	r_socket_read (rtr_host[rtr_n].fd, (ut8*)cmd_output, cmd_len);
	r_cons_printf ("%s\n", cmd_output);
	free ((void *)cmd_output);
}
