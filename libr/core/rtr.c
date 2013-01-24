/* radare - Copyright 2009-2012 - pancake, nibble */

#include "r_core.h"
#include "r_socket.h"

#define endian core->assembler->big_endian
#define rtr_n core->rtr_n
#define rtr_host core->rtr_host

static RSocket *s = NULL;
static const char *listenport = NULL;

static void http_break (void *u) {
	RSocket* sock;
	const char *port;
	const int timeout = 1; // 1 second
	RCore *core = (RCore*)u;
	if (((size_t)u)>0xff) {
		port = listenport? listenport: r_config_get (core->config, "http.port");
		sock = r_socket_new (0);
		r_socket_connect (sock, "localhost", port, R_SOCKET_PROTO_TCP, timeout);
		r_socket_free (sock);
	}
	r_socket_free (s);
	s = NULL;
}

#if 0
SECURITY IMPLICATIONS
- no ssl
- no auth
- commands can be executed by anyone
- default is to listen on localhost
- can access full filesystem
- follow symlinks
#endif

R_API int r_core_rtr_http(RCore *core, int launch, const char *path) {
	RSocketHTTPRequest *rs;
	int oldsandbox = -1;
	int timeout = r_config_get_i (core->config, "http.timeout");
	int x = r_config_get_i (core->config, "scr.html");
	int y = r_config_get_i (core->config, "scr.color");
	int z = r_config_get_i (core->config, "asm.bytes");
	int u = r_config_get_i (core->config, "scr.interactive");
	int v = r_config_get_i (core->config, "asm.cmtright");
	const char *port = r_config_get (core->config, "http.port");
	if (r_sandbox_enable (0)) {
		eprintf ("sandbox: connect disabled\n");
		return 1;
	}
	s = r_socket_new (R_FALSE);
	s->local = !r_config_get_i (core->config, "http.public");
	if (!r_socket_listen (s, port, NULL)) {
		eprintf ("Cannot listen on http.port\n");
		return 1;
	}
	if (launch) {
		char cmd[128];
		const char *browser = r_config_get (core->config, "http.browser");
		snprintf (cmd, sizeof (cmd)-1, "%s http://localhost:%d/%s",
			browser, atoi (port), path?path:"");
		r_sys_cmd (cmd);
	}
	r_config_set (core->config, "asm.cmtright", "false");
	r_config_set (core->config, "scr.html", "true");
	r_config_set (core->config, "scr.color", "false");
	r_config_set (core->config, "asm.bytes", "false");
	r_config_set (core->config, "scr.interactive", "false");
	if (r_config_get_i (core->config, "http.sandbox")) {
		oldsandbox = r_config_get_i (core->config, "cfg.sandbox");
		r_config_set (core->config, "cfg.sandbox", "true");
	}
	eprintf ("Starting http server...\n");
	eprintf ("http://localhost:%d/\n", atoi (port));
	while (!r_cons_singleton ()->breaked) {
		r_cons_break (http_break, core);
		rs = r_socket_http_accept (s, timeout);
		if (!rs) {
			if (!s) break;
			r_sys_usleep (200);
			continue;
		}
		if (!rs->method || !rs->path) {
			r_socket_http_close (rs);
			continue;
		}
		if (!strcmp (rs->method, "GET")) {
			if (!memcmp (rs->path, "/up", 3)) {
				if (r_config_get_i (core->config, "http.upget")) {
					const char *uproot = r_config_get (core->config, "http.uproot");
					if (!rs->path[3] || (rs->path[3]=='/'&&!rs->path[4])) {
						char *ptr = strdup ("<html><body>\n");
						const char *file;
						RListIter *iter;
						// list files
						RList *files = r_sys_dir (uproot);
						eprintf ("Listing directory %s\n", uproot);
						r_list_foreach (files, iter, file) {
							if (file[0] == '.') continue;
							ptr = r_str_concatf (ptr, "<a href=\"/up/%s\">%s</a><br />\n",
								file, file);
						}
						r_list_free (files);
						ptr = r_str_concat (ptr, "<html><body>\n");
						r_socket_http_response (rs, 200, ptr, 0, NULL);
					} else {
						char *path = r_file_root (uproot, rs->path + 4);
						if (r_file_exists (path)) {
							int sz = 0;
							char *f = r_file_slurp (path, &sz);
							if (f) {
								r_socket_http_response (rs, 200, f, sz, NULL);
								free (f);
							} else {
								r_socket_http_response (rs, 403, "Permission denied", 0, NULL);
								eprintf ("http: Cannot open '%s'\n", path);
							}
						} else {
							eprintf ("File '%s' not found\n", path);
							r_socket_http_response (rs, 404, "File not found\n", 0, NULL);
						}
						free (path);
					}
				} else {
					r_socket_http_response (rs, 403,
							"Permission denied\n", 0, NULL);
				}
			} else if (!memcmp (rs->path, "/cmd/", 5)) {
					char *out, *cmd = rs->path+5;
				r_str_uri_decode (cmd);
				out = r_core_cmd_str_pipe (core, cmd);
				if (out) {
					char *res = r_str_uri_encode (out);
					r_socket_http_response (rs, 200, out, 0,
						"Content-Type: text/plain\n");
					free (out);
					free (res);
				} else r_socket_http_response (rs, 200, "", 0, NULL);
			} else {
				const char *root = r_config_get (core->config, "http.root");
				char *path;
				path = r_file_root (root, rs->path);

				if (rs->path [strlen (rs->path)-1] == '/') {
					path = r_str_concat (path, "index.html");
					//rs->path = r_str_concat (rs->path, "index.html");
				} else {
					//snprintf (path, sizeof (path), "%s/%s", root, rs->path);
					if (r_file_is_directory (path)) {
						char res[128];
						snprintf (res, sizeof (res),
							"Location: %s/\n", rs->path);
						r_socket_http_response (rs, 302,
							NULL, 0, res);
						r_socket_http_close (rs);
						free (path);
						continue;
					}
				}
				if (r_file_exists (path)) {
					int sz = 0;
					char *f = r_file_slurp (path, &sz);
					if (f) {
						const char *contenttype = NULL;
						if (strstr (path, ".js")) contenttype = "Content-Type: application/javascript\n";
						if (strstr (path, ".css")) contenttype = "Content-Type: text/css\n";
						if (strstr (path, ".html")) contenttype = "Content-Type: text/html\n";
						r_socket_http_response (rs, 200, f, sz, contenttype);
						free (f);
					} else {
						r_socket_http_response (rs, 403, "Permission denied", 0, NULL);
						eprintf ("http: Cannot open '%s'\n", path);
					}
				} else {
					eprintf ("File '%s' not found\n", path);
					r_socket_http_response (rs, 404, "File not found\n", 0, NULL);
				}
				free (path);
			}
		} else 
		if (!strcmp (rs->method, "POST")) {
			ut8 *ret;
			int retlen;
			char buf[128];
			if (r_config_get_i (core->config, "http.upload")) {
				ret = r_socket_http_handle_upload (
					rs->data, rs->data_length, &retlen);
				if (ret) {
					ut64 size = r_config_get_i (core->config, "http.maxsize");
					if (size && retlen > size) {
						r_socket_http_response (rs, 403, "403 File too big\n", 0, NULL);
					} else {
						char *filename = r_file_root (
							r_config_get (core->config, "http.uproot"),
							rs->path + 4);
						eprintf ("UPLOADED '%s'\n", filename);
						r_file_dump (filename, ret, retlen);
						free (filename);
						snprintf (buf, sizeof (buf),
							"<html><body><h2>uploaded %d bytes. Thanks</h2>\n", retlen);
							r_socket_http_response (rs, 200, buf, 0, NULL);
					}
					free (ret);
				}
			} else {
				r_socket_http_response (rs, 403, "403 Forbidden\n", 0, NULL);
			}
		} else {
			r_socket_http_response (rs, 404, "Invalid protocol", 0, NULL);
		}
		r_socket_http_close (rs);
	}
	r_socket_free (s);
	r_cons_break_end ();
	r_config_set_i (core->config, "scr.html", x);
	r_config_set_i (core->config, "scr.color", y);
	r_config_set_i (core->config, "asm.bytes", z);
	r_config_set_i (core->config, "scr.interactive", u);
	r_config_set_i (core->config, "asm.cmtright", v);
	if (oldsandbox != -1)
		r_config_set_i (core->config, "cfg.sandbox", oldsandbox);
	return 0;
}

R_API void r_core_rtr_help(RCore *core) {
	r_cons_printf (
	"remote commands:\n"
	" =:port              listen on given port using rap protocol (o rap://9999)\n"
	" =:host:port cmd     run 'cmd' command on remote server.\n"
	"rap commands:\n"
	" =                   list all open connections\n"
	//" =:port [cmd]      ; same as .: but allow to send command if cmd\n"
	" =<[fd] cmd          send output of local command to remote fd\n"
	" =[fd] cmd           exec cmd at remote 'fd' (last open is default one)\n"
	" =! cmd              run command via r_io_system\n"
	" =+ [proto://]host   add host (default=rap://, tcp://, udp://)\n"
	" =-[fd]              remove all hosts or host 'fd'\n"
	" ==[fd]              open remote session with host 'fd', 'q' to quit\n"
	"http server:\n"
	" =h                  listen for http connections (r2 -qc=H /bin/ls)\n"
	" =H                  launch browser and listen for http\n");
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
	while (*host && iswhitechar (*host))
		host++;

	if (!(ptr = strchr (host, ':'))) {
		eprintf ("Error: Port is not specified\n");
		return;
	}
	*ptr++ = '\0';

	if (!(file = strchr (ptr, '/'))) {
		eprintf("Error: Missing '/'\n");
		return;
	}
	*file++ = 0;
	port = ptr;

	fd = r_socket_new (R_FALSE);
	if (!fd) {
		eprintf ("Error: Cannot create new socket\n");
		return;
	}
	switch (proto) {
	case RTR_PROT_RAP:
		if (r_sandbox_enable (0)) {
			eprintf ("sandbox: connect disabled\n");
			return;
		}
		if (!r_socket_connect_tcp (fd, host, port, 10)) { //TODO: Use rap.ssl
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
		if (r_sandbox_enable (0)) {
			eprintf ("sandbox: connect disabled\n");
			return;
		}
		if (!r_socket_connect_tcp (fd, host, port, 10)) { //TODO: Use rap.ssl
			eprintf("Error: Cannot connect to '%s' (%s)\n", host, port);
			return;
		}
		eprintf ("Connected to: %s at port %s\n", host, port);
		break;
	case RTR_PROT_UDP:
		if (r_sandbox_enable (0)) {
			eprintf ("sandbox: connect disabled\n");
			return;
		}
		if (!r_socket_connect_udp (fd, host, port, 30)) { //TODO: Use rap.ssl
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
			rtr_host[i].port = atoi (port);
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
		for (rtr_n = 0; rtr_host[rtr_n].fd->fd != fd \
			&& rtr_n < RTR_MAX_HOSTS; rtr_n++);
	}

	for (;;) {
		if (rtr_host[rtr_n].fd)
			snprintf (prompt, sizeof (prompt),
				"fd:%d> ", rtr_host[rtr_n].fd->fd);
		free (r_line_singleton ()->prompt);
		r_line_singleton ()->prompt = strdup (prompt);
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

	if (*input==':' && !strchr (input+1, ':')) {
		r_core_cmdf (core, "o rap://%s", input);
		return;
	}
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

// TODO: support len for binary data?
R_API char *r_core_rtr_cmds_query (RCore *core, const char *host, const char *port, const char *cmd) {
	int retries = 6;
	unsigned char buf[1024];
	char *rbuf = NULL;
	const int timeout = 0;
	RSocket *s = r_socket_new (0);
	for (;retries>0; r_sys_usleep (10*1000)) {
		if (r_socket_connect (s, host, port, R_SOCKET_PROTO_TCP, timeout))
			break;
		retries--;
	}
	if (retries>0) {
		rbuf = strdup ("");
		r_socket_write (s, (void*)cmd, strlen (cmd));
		//r_socket_write (s, "px\n", 3);
		for (;;) {
			int ret = r_socket_read (s, buf, sizeof (buf));
			if (ret<1) break;
			buf[ret] = 0;
			rbuf = r_str_concat (rbuf, (const char *)buf);
		}
	} else {
		eprintf ("Cannot connect\n");
	}
	r_socket_free (s);
	return rbuf;
}

R_API int r_core_rtr_cmds (RCore *core, const char *port) {
	unsigned char buf[4096];
	RSocket *ch, *s;
	int i, ret;
	char *str;

	if (!port || port[0]=='?') {
		r_cons_printf ("Usage: .:[tcp-port]    run r2 commands for clients\n");
		return R_FALSE;
	}

	s = r_socket_new (0);
	if (!r_socket_listen (s, port, NULL)) {
		eprintf ("Error listening on port %s\n", port);
		r_socket_free (s);
		return R_FALSE;
	}
	
	eprintf ("Listening for commands on port %s\n", port);
	listenport = port;
	for (;;) {
		r_cons_break (http_break, core);
		ch = r_socket_accept (s);
		buf[0] = 0;
		ret = r_socket_read (ch, buf, sizeof (buf));
		if (ret>0) {
			buf[ret] = 0;
			for (i=0; buf[i]; i++)
				if (buf[i] == '\n')
					buf[i] = buf[i+1]? ';': '\0';
			if (!r_config_get_i (core->config, "scr.prompt") \
					&& !strcmp ((char*)buf, "q!"))
				break;
			str = r_core_cmd_str (core, (const char *)buf);
			if (str &&*str)  {
			r_socket_write (ch, str, strlen (str));
			} else 
			r_socket_write (ch, "\n", 1);
			free (str);
		}
		if (r_cons_singleton()->breaked) break;
		r_socket_close (ch);
		r_cons_break_end ();
	}
	return 0;
}
