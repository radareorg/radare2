/* radare - LGPL - Copyright 2011-2020 - pancake */

#include <r_socket.h>
#include <r_util.h>

static size_t __socket_slurp(RSocket *s, RBuffer *buf) {
	size_t i;
	if (r_socket_ready (s, 1, 0) != 1) {
		return 0;
	}
	r_socket_block_time (s, 1, 0, 1000);
	for (i = 0; i < 0x2000; i += 1) {
		ut8 c;
		int olen = r_socket_read_block (s, &c, 1);
		if (olen != 1) {
			r_buf_append_bytes (buf, (ut8 *)"", 1);
			break;
		}
		r_buf_append_bytes (buf, &c, 1);
	}
	return i;
}

static char *__recurse_redirect(const char *url, int *code, int *rlen) {
	static size_t depth = 0;
	if (depth >= 5) {
		eprintf ("Too many redirects\n");
		return NULL;
	}
	depth++;
	char *ret = r_socket_http_get (url, code, rlen);
	depth--;
	return ret;
}

static char *r_socket_http_answer(RSocket *s, int *code, int *rlen) {
	r_return_val_if_fail (s, NULL);
	const char *p;
	int ret, len = 0, delta = 0;
	char *dn;
	RBuffer *b = r_buf_new ();
	if (!b) {
		return NULL;
	}
	char *res = NULL;
	size_t olen = __socket_slurp (s, b);
	char *buf = malloc (olen + 1);
	r_buf_read_at (b, 0, (ut8 *)buf, olen);
	buf[olen] = 0;
	if ((dn = (char*)r_str_casestr (buf, "\n\n"))) {
		delta += 2;
	} else if ((dn = (char*)r_str_casestr (buf, "\r\n\r\n"))) {
		delta += 4;
	} else {
		goto exit;
	}

	olen -= delta;
	*dn = 0; // chop headers

	/* Follow redirects */
	p = r_str_casestr (buf, "Location:");
	if (p) {
		p += strlen ("Location:");
		int url_len = strchr (p, '\n') - p;
		char *url = r_str_ndup (p, url_len);
		r_str_trim (url);
		res = __recurse_redirect (url, code, rlen);
		free (url);
		len = *rlen;
		goto exit;
	}

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
			olen -= dn - buf;
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
exit:
	free (buf);
	r_buf_free (b);
	r_socket_close (s);
	if (rlen) {
		*rlen = len;
	}
	return res;
}

R_API char *r_socket_http_get(const char *url, int *code, int *rlen) {
	char *curl_env = r_sys_getenv ("R2_CURL");
	if (curl_env && atoi (curl_env)) {
		int len;
		char *escaped_url = r_str_escape_sh (url);
		char *command = r_str_newf ("curl -sfL -o - \"%s\"", escaped_url);
		char *res = r_sys_cmd_str (command, NULL, &len);
		free (escaped_url);
		free (command);
		free (curl_env);
		if (!res) {
			return NULL;
		}
		if (res) {
			if (code) {
				*code = 200;
			}
			if (rlen) {
				*rlen = len;
			}
		}
		return res;
	}
	free (curl_env);
	RSocket *s;
	int ssl = r_str_startswith (url, "https://");
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
		port = ssl? "443": "80";
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

R_API char *r_socket_http_post(const char *url, const char *data, int *code, int *rlen) {
	RSocket *s;
	bool ssl = r_str_startswith (url, "https://");
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
