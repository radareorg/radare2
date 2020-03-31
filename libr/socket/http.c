/* radare - LGPL - Copyright 2011-2019 - pancake */

#include <r_socket.h>
#include <r_util.h>

static int __socket_slurp (RSocket *s, ut8 *buf, int bufsz) {
	int i;
	int chsz = 1;
	// r_socket_block_time (s, 1, 1, 0);
	if (r_socket_read_block (s, (ut8 *) buf, 1) != 1) {
		return 0;
	}
	for (i = 1; i < bufsz; i += chsz) {
		buf[i] =0;
		r_socket_block_time (s, 1, 0, 1000);
		int olen = r_socket_read_block (s, (ut8 *) buf + i , chsz);
		if (olen != chsz) {
			buf[i] = 0;
			break;
		}
	}
	return i;
}

static char *r_socket_http_answer (RSocket *s, int *code, int *rlen) {
	r_return_val_if_fail (s, NULL);
	const char *p;
	int ret, len = 0, bufsz = 32768, delta = 0;
	char *dn, *buf = calloc (1, bufsz + 32); // XXX: use r_buffer here
	if (!buf) {
		return NULL;
	}
	char *res = NULL;
	int olen = __socket_slurp (s, (ut8*)buf, bufsz);
	if ((dn = (char*)r_str_casestr (buf, "\n\n"))) {
		delta += 2;
	} else if ((dn = (char*)r_str_casestr (buf, "\r\n\r\n"))) {
		delta += 4;
	} else {
		goto fail;
	}

	olen -= delta;
	*dn = 0; // chop headers
	/* Parse Len */
	p = r_str_casestr (buf, "Content-Length: ");
	if (p) {
		len = atoi (p + 16);
	} else {
		len = olen - (dn - buf);
	}
	if (len > 0) {
		if (len > olen) {
			res = malloc (len + 2);
			memcpy (res, dn + delta, olen);
			do {
				ret = r_socket_read_block (s, (ut8*) res + olen, len - olen);
				if (ret < 1) {
					break;
				}
				olen += ret;
			} while (olen < len);
			res[len] = 0;
		} else {
			res = malloc (len + 1);
			if (res) {
				memcpy (res, dn + delta, len);
				res[len] = 0;
			}
		}
	} else {
		res = NULL;
	}
fail:
	free (buf);
// is 's' free'd? isn't this going to cause a double free?
	r_socket_close (s);
	if (rlen) {
		*rlen = len;
	}
	return res;
}

R_API char *r_socket_http_get (const char *url, int *code, int *rlen) {
	char *curl_env = r_sys_getenv ("R2_CURL");
	if (curl_env && *curl_env) {
		char *encoded_url = r_str_escape (url);
		char *res = r_sys_cmd_strf ("curl '%s'", encoded_url);
		free (encoded_url);
		if (res) {
			if (code) {
				*code = 200;
			}
			if (rlen) {
				*rlen = strlen (res);
			}
		}
		free (curl_env);
		return res;
	}
	free (curl_env);
	RSocket *s;
	int ssl = !memcmp (url, "https://", 8);
	char *response, *host, *path, *port = "80";
	char *uri = strdup (url);
	if (!uri) {
		return NULL;
	}

	if (code) {
		*code = 0;
	}
	if (rlen) {
		*rlen = 0;
	}
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
	if (!path) {
		path = "";
	} else {
		*path++ = 0;
	}
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
	bool ssl = !memcmp (url, "https://", 8);
	char *uri = strdup (url);
	if (!uri) {
		return NULL;
	}

	char *host = strstr (uri, "://");
	if (!host) {
		free (uri);
		printf ("Invalid URI");
		return NULL;
	}
	host += 3;
	char *port = strchr (host, ':');
	if (!port) {
		port = (ssl)? "443": "80";
	} else {
		*port++ = 0;
	}
	char *path = strchr (host, '/');
	if (!path) {
		path = "";
	} else {
		*path++ = 0;
	}
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
			"\r\n", path, host, (int)strlen (data));
	free (uri);
	r_socket_write (s, (void *)data, strlen (data));
	return r_socket_http_answer (s, code, rlen);
}

#if TEST
void main () {
	int ret;
	char *p = r_socket_http_post ("http://www.radare.org/y/index.php", "a=b", &ret);
	printf ("%s\n", p);
}
#endif
