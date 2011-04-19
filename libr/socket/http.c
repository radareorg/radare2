/* radare - LGPL - Copyright 2011 pancake<nopcode.org> */

#include <r_socket.h>

static char *r_socket_http_response (RSocket *s, int *code) {
	char buf[32768];
	char *p, *q;
	int i, len;

	/* Read Header */
	i = 0;
	do {
		len = r_socket_gets (s, buf+i, sizeof (buf)-i);
		i += len;
		r_socket_gets (s, buf+i, 1);
		buf[i++]='\n';
	} while (len > 0);
	/* Parse Code */
	p = strchr (buf, ' ');
	*code = (p)?atoi (p+1):-1;
	/* Parse Len */
	p = strstr (buf, "Content-Length: ");
	len = (p)?atoi (p+16):0;
	/* Read Content */
	len = r_socket_read_block (s, buf+i, len);
	r_socket_close (s);
	return strdup (buf);
}

R_API char *r_socket_http_get (const char *url, int *code) {
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
	s = r_socket_new (host, port, ssl);
	if (!s) {
		printf ("Cannot connect\n");
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
	response = r_socket_http_response (s, code);
	free (uri);
	return response;
}

R_API char *r_socket_http_post (const char *url, const char *data, int *code) {
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
	s = r_socket_new (host, port, ssl);
	if (!s) {
		printf ("Cannot connect\n");
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
	response = r_socket_http_response (s, code);
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
