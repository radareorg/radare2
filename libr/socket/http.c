/* radare - LGPL - Copyright 2011-2013 - pancake */

#include <r_socket.h>
#include <r_util.h>

static char *r_socket_http_answer (RSocket *s, int *code, int *rlen) {
	const char *p;
	int ret, olen, len = 0, bufsz = 32768, delta = 0;
	char *dn, *res, *buf = malloc (bufsz); // XXX: use r_buffer here

	res = NULL;
	olen = r_socket_read_block (s, (unsigned char*) buf, bufsz);
	if (olen < 1) goto fail;

	if ((dn = (char*)r_str_casestr (buf, "\n\n"))) {
		delta += 2;
	} else if ((dn = (char*)r_str_casestr (buf, "\r\n\r\n"))) {
		delta += 4;
	} else goto fail;

	olen -= delta;
	*dn = 0; // chop headers
	/* Parse Len */
	p = r_str_casestr (buf, "Content-Length: ");
	if (p) len = atoi (p+16);
	else len = olen - (dn - buf);

	if (len >0) {
		if (len > olen) {
			res = malloc (len+1);
			memcpy (res, dn+delta, olen);
			do {
				ret = r_socket_read_block (s,
					(ut8*) res+olen, len-olen);
				if (ret < 1)
					break;
				olen += ret;
			} while (olen<len);
			res[len] = 0;
		} else {
			res = malloc (len+1);
			if (res) {
				memcpy (res, dn+delta, len);
				res[len] = 0;
			}
		}
	} else res = NULL;
fail:
	free (buf);
// is 's' free'd? isnt this going to cause a double free?
	r_socket_close (s);
	if (rlen) *rlen = len;
	return res;
}

R_API char *r_socket_http_get (const char *url, int *code, int *rlen) {
	RSocket *s;
	int ssl = !memcmp (url, "https://", 8);
	char *response, *host, *path, *port = "80";
	char *uri = strdup (url);

	host = strstr (uri, "://");
	if (!host) {
		free (uri);
		eprintf ("r_socket_http_get: Invalid URI");
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
		eprintf ("r_socket_http_get: Cannot create socket\n");
		free (uri);
		return NULL;
	}
	if (r_socket_connect_tcp (s, host, port, 0)) {
		r_socket_printf (s,
				"GET /%s HTTP/1.1\r\n"
				"User-Agent: radare2 "R2_VERSION"\r\n"
				"Accept: */*\r\n"
				"Host: %s:%s\r\n"
				"\r\n", path, host, port);
		response = r_socket_http_answer (s, code, rlen);
	} else {
		eprintf ("Cannot connect to %s:%s\n", host, port);
		response = NULL;
	}
	free (uri);
	r_socket_free (s);
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
