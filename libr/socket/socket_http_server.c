/* radare - LGPL - Copyright 2012-2025 - pancake */

#include <r_socket.h>
#include <r_util.h>

static R_TH_LOCAL bool *breaked = NULL;

R_API void r_socket_http_server_set_breaked(bool *b) {
	breaked = b;
}

R_API RSocketHTTPRequest *r_socket_http_accept(RSocket *s, RSocketHTTPOptions *so) {
	int content_length = 0, xx, yy;
	int pxx = 1, first = 0;
	char buf[1500], *p, *q;
	RSocketHTTPRequest *hr = R_NEW0 (RSocketHTTPRequest);
	if (so->accept_timeout) {
		hr->s = r_socket_accept_timeout (s, 1);
	} else {
		hr->s = r_socket_accept (s);
	}
	if (!hr->s) {
		free (hr);
		return NULL;
	}
	if (so->timeout > 0) {
		r_socket_block_time (hr->s, true, so->timeout, 0);
	}
	hr->auth = !so->httpauth;
	for (;;) {
#if R2__WINDOWS__
		if (breaked && *breaked) {
			r_socket_http_close (hr);
			r_socket_free (hr->s);
			return NULL;
		}
#endif
		memset (buf, 0, sizeof (buf));
		xx = r_socket_gets (hr->s, buf, sizeof (buf));
		yy = r_socket_ready (hr->s, 0, 20 * 1000); // this function uses usecs as argument
		//		eprintf ("READ %d (%s) READY %d\n", xx, buf, yy);
		if (!yy || (!xx && !pxx)) {
			break;
		}
		pxx = xx;

		if (first == 0) {
			first = 1;
			if (strlen (buf) < 3) {
				r_socket_http_close (hr);
				r_socket_free (hr->s);
				free (hr);
				return NULL;
			}
			p = strchr (buf, ' ');
			if (p) {
				*p = 0;
			}
			hr->method = strdup (buf);
			if (p) {
				q = strstr (p + 1, " HTTP");
				if (q) {
					*q = 0;
				}
				hr->path = r_str_trim_dup (p + 1);
			}
		} else {
			if (!hr->referer && r_str_startswith (buf, "Referer: ")) {
				hr->referer = strdup (buf + 9);
			} else if (!hr->agent && r_str_startswith (buf, "User-Agent: ")) {
				hr->agent = strdup (buf + 12);
			} else if (!hr->host && r_str_startswith (buf, "Host: ")) {
				hr->host = strdup (buf + 6);
			} else if (r_str_startswith (buf, "Content-Length: ")) {
				content_length = atoi (buf + 16);
			} else if (so->httpauth && r_str_startswith (buf, "Authorization: Basic ")) {
				char *authtoken = buf + 21;
				size_t authlen = strlen (authtoken);
				char *decauthtoken = calloc (4, authlen + 1);
				if (!decauthtoken) {
					return hr;
				}
				if (r_base64_decode ( (ut8 *)decauthtoken, authtoken, authlen) == -1) {
					R_LOG_ERROR ("Could not decode authorization token");
				} else {
					RListIter *iter;
					char *curauthtoken;
					r_list_foreach (so->authtokens, iter, curauthtoken) {
						if (!strcmp (decauthtoken, curauthtoken)) {
							hr->auth = true;
							break;
						}
					}
				}
				free (decauthtoken);
				if (!hr->auth) {
					R_LOG_ERROR ("Failed attempt login from '%s'", hr->host);
				}
			}
		}
	}
	if (content_length > 0) {
		r_socket_read_block (hr->s, (ut8 *)buf, 1); // one missing byte wtf
		if (content_length >= ST32_MAX) {
			r_socket_http_close (hr);
			r_socket_free (hr->s);
			R_LOG_ERROR ("Could not allocate hr data");
			return NULL;
		}
		hr->data = malloc (content_length + 1);
		if (hr->data) {
			hr->data_length = content_length;
			if (buf[0] == '\r' || buf[0] == '\n') {
				/* discarded leftover newline; now read the body */
				r_socket_read_block (hr->s, hr->data, hr->data_length);
			} else {
				/* first byte belongs to body */
				hr->data[0] = buf[0];
				if (hr->data_length > 1) {
					r_socket_read_block (hr->s, (ut8 *) (hr->data + 1), hr->data_length - 1);
				}
			}
			hr->data[content_length] = 0;
		}
	}
	return hr;
}

R_API void r_socket_http_response(RSocketHTTPRequest *rs, int code, const char *out, int len, const char *headers) {
	R_RETURN_IF_FAIL (rs);
	const char *strcode =
		code == 200 ? "ok" : code == 301 ? "Moved permanently" :
		code == 302 ? "Found" :
		code == 401 ? "Unauthorized" :
		code == 403 ? "Permission denied" :
		code == 404 ? "not found" :
		"UNKNOWN";
	if (len < 1) {
		len = out ? strlen (out) : 0;
	}
	if (!headers) {
		headers = code == 401 ? "WWW-Authenticate: Basic realm=\"R2 Web UI Access\"\n" : "";
	}
	r_socket_printf (rs->s, "HTTP/1.0 %d %s\r\n%s"
			       "Connection: close\r\nContent-Length: %d\r\n\r\n",
		code, strcode, headers, len);
	if (out && len > 0) {
		r_socket_write (rs->s, (void *)out, len);
	}
}

R_API ut8 *r_socket_http_handle_upload(const ut8 *str, int len, int *retlen) {
	if (retlen) {
		*retlen = 0;
	}
	if (!strncmp ( (const char *)str, "----------", 10)) {
		int datalen;
		char *ret;
		const char *data, *token = (const char *)str + 10;
		const char *end = strchr (token, '\n');
		if (!end) {
			return NULL;
		}
		data = strstr (end, "Content-Disposition: form-data; ");
		if (data) {
			data = strchr (data, '\n');
			if (data) {
				data = strchr (data + 1, '\n');
			}
		}
		if (data) {
			while (*data == 10 || *data == 13) {
				data++;
			}
			end = (const char *)str + len - 40;
			while (*end == '-') {
				end--;
			}
			if (*end == 10 || *end == 13) {
				end--;
			}
			datalen = (size_t) (end - data);
			ret = malloc (datalen + 1);
			if (!ret) {
				return NULL;
			}
			memcpy (ret, data, datalen);
			ret[datalen] = 0;
			if (retlen) {
				*retlen = datalen;
			}
			return (ut8 *)ret;
		}
	}
	return NULL;
}

R_API void r_socket_http_close(RSocketHTTPRequest *rs) {
	if (rs) {
		r_socket_close (rs->s);
	}
}

/* close client socket and free struct */
R_API void r_socket_http_free(RSocketHTTPRequest *rs) {
	if (rs) {
		r_socket_free (rs->s);
		free (rs->path);
		free (rs->host);
		free (rs->agent);
		free (rs->method);
		free (rs->data);
		free (rs);
	}
}

#if MAIN
int main () {
	RSocket *s = r_socket_new (false);
	if (!r_socket_listen (s, "8080", NULL)) {
		R_LOG_ERROR ("Cannot listen here");
		return 1;
	}
	for (;;) {
		RSocketHTTPRequest *rs = r_socket_http_accept (s, 0);
		if (!rs) {
			continue;
		}
		if (!strcmp (rs->method, "GET")) {
			r_socket_http_response (rs, 200,
				"<html><body><form method=post action=/>"
				"<input name=a /><input type=button></form></body>");
		} else if (!strcmp (rs->method, "POST")) {
			char *buf = malloc (rs->data_length + 50);
			if (buf) {
				strcpy (buf, "<html><body><h2>XSS test</h2>\n");
				r_str_unescape (rs->data);
				strcat (buf, rs->data);
				r_socket_http_response (rs, 200, buf);
				free (buf);
			} else {
				R_LOG_ERROR ("Cannot allocate %d bytes", rs->data_length + 50);
			}
		} else if (!strcmp (rs->method, "OPTIONS")) {
			r_socket_http_response (rs, 200, "");
		} else {
			r_socket_http_response (rs, 404, "Invalid protocol");
		}
		r_socket_http_close (rs);
		r_socket_http_free (rs);
	}
}
#endif
