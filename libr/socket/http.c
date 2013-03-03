/* radare - LGPL - Copyright 2011-2013 - pancake */

#include <r_socket.h>
#include <r_util.h>

static char *r_socket_http_answer (RSocket *s, int *code, int *rlen) {
	const char *p;
	int i, line, len, bufsz = 32768;
	char *buf = malloc (bufsz); // XXX: use r_buffer here
	/* Read Header */
	int llen = 01234;
	line = i = 0;
	int isremote = 0;
	do {
		line ++;
		len = r_socket_gets (s, buf+i, bufsz-i);
		if (len<0) {
			break;
		}
		if (len == 0) {
			if (!isremote && line>2) break;
			if (isremote && llen == 0) break;
			if (!isremote) {
				if (line==2) {
					isremote = 1;
				} else {
					if (line>2) isremote = 1;
				}
			}
			llen = len;
			continue;
		}
		llen = len;
		i += len;
		buf[i++] = '\n';
	} while (1); //i==0 || len > 0);
	buf[i] = 0;
	/* Parse Code */
	p = strchr (buf, ' ');
	if (code) *code = (p)? atoi (p+1):-1;
	/* Parse Len */
	p = r_str_casestr (buf, "Content-Length: ");
	if (p) {
		len = atoi (p+16);
		free (buf);
		buf = malloc (len+1);
		if (len>0) {
			if (isremote) {
				int j = 0;
				while (j<len) {
					len = r_socket_read (s, (ut8*)buf+j, len-j);
					if (len<1) break;
					j+=len;
				}
			} else len = r_socket_read_block (s, (ut8*)buf, len);
		} else len = 0;
	} else {
		// hack
		len = 32768-i;
		len = r_socket_read (s, (ut8*)buf+i, len);
#if 0
p = strstr(buf, "\n\n");
if (!p) p = strstr (buf, "\n\r\n");
if (p) strcpy (buf, p+2);
len = strlen (buf);
#endif
	}
	r_socket_close (s);
	if (rlen) *rlen = len;
	return buf;
}

R_API char *r_socket_http_get (const char *url, int *code, int *rlen) {
	RSocket *s;
	int ssl = !memcmp (url, "https://", 8);
	char *response, *host, *path, *port = "80";
	char *uri = strdup (url);

	host = strstr (uri, "://");
	if (!host) {
		free (uri);
		printf ("Invalid URI");
		return NULL;
	}
	host += 3;
	port = strchr (host, ':');
	if (!port) {
		port = (ssl)?"443":"80";
		path = host;
	} else {
		*port++ = 0;
		path = port;
	}
	path = strchr (path, '/');
	if (!path) path = "";
	else *path++ = 0;
	s = r_socket_new (ssl);
	if (!s) {
		printf ("Cannot create socket\n");
		free (uri);
		return NULL;
	}
	if (!r_socket_connect_tcp (s, host, port, 0)) {
		eprintf ("Cannot connect to %s:%s\n", host, port);
		free (uri);
		return NULL;
	}
	/* Send */
	r_socket_printf (s,
			"GET /%s HTTP/1.1\r\n"
			"User-Agent: radare2 "R2_VERSION"\r\n"
			"Accept: */*\r\n"
			"Host: %s\r\n"
			"\r\n", path, host);
	response = r_socket_http_answer (s, code, rlen);
	free (uri);
	return response;
}

R_API char *r_socket_http_post (const char *url, const char *data, int *code, int *rlen) {
	RSocket *s;
	int ssl = !memcmp (url, "https://", 8);
	char *response, *host, *path, *port = "80";
	char *uri = strdup (url);

	host = strstr (uri, "://");
	if (!host) {
		free (uri);
		printf ("Invalid URI");
		return NULL;
	}
	host += 3;
	port = strchr (host, ':');
	if (!port)
		port = (ssl)?"443":"80";
	else
		*port++ = 0;
	path = strchr (host, '/');
	if (!path)
		path = "";
	else
		*path++ = 0;
	s = r_socket_new (ssl);
	if (!s) {
		printf ("Cannot create socket\n");
		free (uri);
		return NULL;
	}
	if (!r_socket_connect_tcp (s, host, port, 0)) {
		eprintf ("Cannot connect to %s:%s\n", host, port);
		free (uri);
		return NULL;
	}
	/* Send */
	r_socket_printf (s,
			"POST /%s HTTP/1.0\r\n"
			"User-Agent: radare2 "R2_VERSION"\r\n"
			"Accept: */*\r\n"
			"Host: %s\r\n"
			"Content-Length: %i\r\n"
			"Content-Type: application/x-www-form-urlencoded\r\n"
			"\r\n", path, host, strlen (data));
	r_socket_write (s, (void *)data, strlen (data));
	response = r_socket_http_answer (s, code, rlen);
	free (uri);
	return response;
}

#if TEST
void main () {
	int ret;
	char *p = r_socket_http_post ("http://www.radare.org/y/index.php", "a=b", &ret);
	printf ("%s\n", p);
}
#endif
