/* radare - LGPL - Copyright 2011-2025 - pancake */

#include <r_socket.h>
#include <r_util.h>

#if R2__WINDOWS__
#include <wininet.h>
#endif

#define SOCKET_HTTP_MAX_HEADER_LENGTH 0x2000
#define SOCKET_HTTP_MAX_REDIRECTS 5

static size_t socket_slurp(RSocket *s, RBuffer *buf) {
	size_t i;
	if (r_socket_ready (s, 1, 0) != 1) {
		return 0;
	}
	r_socket_block_time (s, true, 1, 0);
	for (i = 0; i < SOCKET_HTTP_MAX_HEADER_LENGTH; i += 1) {
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

static char *socket_http_get_recursive(const char *url, const char *headers[], int *code, int *rlen, ut32 redirections);

static char *socket_http_answer(RSocket *s, const char *headers[], int *code, int *rlen, ut32 redirections) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	const char *p;
	int ret, len = 0, delta = 0;
	char *dn = NULL;
	RBuffer *b = r_buf_new ();
	if (!b) {
		return NULL;
	}
	char *res = NULL;
	size_t olen = socket_slurp (s, b);
	char *buf = malloc (olen + 1);
	if (!buf) {
		goto exit;
	}
	r_buf_read_at (b, 0, (ut8 *)buf, olen);
	buf[olen] = 0;
	char *dnn = (char *)r_str_casestr (buf, "\n\n");
	char *drn = (char *)r_str_casestr (buf, "\r\n\r\n");
	if (dnn) {
		if (drn && (drn < dnn)) {
			dn = drn;
			delta = 4;
		} else {
			dn = dnn;
			delta = 2;
		}
	} else {
		dn = drn;
		delta = 4;
	}
	if (!dn) {
		goto exit;
	}

	olen -= delta;
	*dn = 0; // chop headers

	/* Follow redirects */
	p = r_str_casestr (buf, "Location:");
	if (p) {
		if (!redirections) {
			R_LOG_ERROR ("Too many redirects");
			goto exit;
		}
		p += strlen ("Location:");
		char *end_url = strchr (p, '\n');
		if (end_url) {
			int url_len = end_url - p;
			char *url = r_str_ndup (p, url_len);
			r_str_trim (url);
			res = socket_http_get_recursive (url, headers, code, rlen, --redirections);
			free (url);
			len = *rlen;
		}
		goto exit;
	}

	/* Parse Len */
	p = r_str_casestr (buf, "Content-Length: ");
	if (p) {
		len = atoi (p + 16);
	} else {
		len = olen - (dn - buf);
	}
	if (len == 0) {
		R_LOG_DEBUG ("LEN = 0");
	}
	if (len > 0) {
		if (len > olen) {
			res = malloc (len + 2);
			if (!res) {
				goto exit;
			}
			olen -= (dn - buf);
			memcpy (res, dn + delta, olen);
			do {
				ret = r_socket_read_block (s, (ut8 *)res + olen, len - olen);
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
		res = strdup ("");
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

#if R2__WINDOWS__
static char *http_get_w32(const char *url, int *code, int *rlen) {
	HINTERNET hInternet = InternetOpenA ("radare2 " R2_VERSION, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hInternet) {
		r_sys_perror ("InternetOpenA");
		return NULL;
	}
	HINTERNET hOpenUrl = InternetOpenUrlA (hInternet, url, NULL, 0, 0, 0);
	if (!hOpenUrl) {
		r_sys_perror ("InternetOpenUrlA");
		InternetCloseHandle (hInternet);
		return NULL;
	}

	char *ret = NULL;
	size_t read_sz = 0x100000;
	DWORD r = 0, w = 0;
	bool res = true;
	do {
		w += r;
		if (!res && GetLastError () == ERROR_INSUFFICIENT_BUFFER) {
			read_sz *= 2;
		}
		char *tmp = realloc (ret, read_sz + w);
		if (!tmp) {
			R_FREE (ret);
			goto exit;
		}
		ret = tmp;
	} while (! (res = InternetReadFile (hOpenUrl, ret + w, read_sz, &r)) || r);

	if (res) {
		char *tmp = realloc (ret, (size_t)w + 1);
		if (tmp) {
			ret = tmp;
			ret[w] = 0;
		} else {
			R_FREE (ret);
		}
	} else {
		R_FREE (ret);
	}

exit:
	if (rlen) {
		*rlen = w;
	}
	if (code && w) {
		*code = 200;
	}
	InternetCloseHandle (hInternet);
	InternetCloseHandle (hOpenUrl);
	return ret;
}
#endif

static char *socket_http_get_recursive(const char *url, const char **headers, int *code, int *rlen, ut32 redirections) {
	if (code) {
		*code = 0;
	}
	if (rlen) {
		*rlen = 0;
	}
	if (r_sys_getenv_asbool ("R2_CURL")) {
		char *header_file = r_file_temp ("r2_http_hdr");
		char *body_file = r_file_temp ("r2_http_body");
		if (!header_file || !body_file) {
			free (header_file);
			free (body_file);
			return NULL;
		}
		char *escaped_header_file = r_str_escape_sh (header_file);
		char *escaped_body_file = r_str_escape_sh (body_file);
		if (!escaped_header_file || !escaped_body_file) {
			free (header_file);
			free (body_file);
			free (escaped_header_file);
			free (escaped_body_file);
			return NULL;
		}
		char *escaped_url = r_str_escape_sh (url);
		if (!escaped_url) {
			free (header_file);
			free (body_file);
			free (escaped_header_file);
			free (escaped_body_file);
			return NULL;
		}
		RStrBuf *sb = r_strbuf_new ("curl -s -D ");
		r_strbuf_appendf (sb, "'%s' -o '%s' -L --max-redirs %u", escaped_header_file, escaped_body_file, redirections);
		if (headers) {
			const char **header = headers;
			while (*header) {
				char *escaped_header = r_str_escape_sh (*header);
				if (!escaped_header) {
					r_strbuf_free (sb);
					free (escaped_url);
					free (escaped_header_file);
					free (escaped_body_file);
					free (header_file);
					free (body_file);
					return NULL;
				}
				r_strbuf_appendf (sb, " -H '%s'", escaped_header);
				free (escaped_header);
				header++;
			}
		}
		r_strbuf_appendf (sb, " '%s'", escaped_url);
		char *command = r_strbuf_drain (sb);
		free (escaped_url);
		free (escaped_header_file);
		free (escaped_body_file);

		int cmd_result = r_sys_cmd (command);
		free (command);

		if (cmd_result != 0) {
			r_file_rm (header_file);
			r_file_rm (body_file);
			free (header_file);
			free (body_file);
			if (code) {
				*code = 500;
			}
			return NULL;
		}

		// Parse status code from header file
		size_t hdr_len;
		char *hdr_content = r_file_slurp (header_file, &hdr_len);
		if (hdr_content) {
			if (code) {
				char *status_line = strstr (hdr_content, "HTTP/");
				if (status_line) {
					char *space = strchr (status_line, ' ');
					if (space) {
						*code = atoi (space + 1);
					} else {
						*code = 200;
					}
				} else {
					*code = 200;
				}
			}
			free (hdr_content);
		} else {
			if (code) {
				*code = 200;
			}
		}

		// Read body
		size_t body_len;
		char *res = r_file_slurp (body_file, &body_len);
		if (rlen) {
			*rlen = body_len;
		}

		r_file_rm (header_file);
		r_file_rm (body_file);
		free (header_file);
		free (body_file);
		return res;
	}
#if R2__WINDOWS__
	return http_get_w32 (url, code, rlen);
#else
	RSocket *s;
	bool ssl = r_str_startswith (url, "https://");
#if !HAVE_LIB_SSL
	if (ssl) {
		R_LOG_ERROR ("Tried to get '%s', but SSL support is disabled, set R2_CURL=1 to use curl", url);
		return NULL;
	}
#endif
	char *response, *host, *path, *port = "80";
	char *uri = strdup (url);
	if (!uri) {
		return NULL;
	}
	host = strstr (uri, "://");
	if (!host) {
		free (uri);
		R_LOG_ERROR ("r_socket_http_get: Invalid URI");
		return NULL;
	}
	host += 3;
	port = strchr (host, ':');
	if (!port) {
#if HAVE_LIB_SSL
		port = ssl? "443": "80";
#else
		port = "80";
#endif
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
		R_LOG_ERROR ("Cannot create socket");
		free (uri);
		return NULL;
	}
	if (r_socket_connect_tcp (s, host, port, 0)) {
		r_socket_printf (s,
			"GET /%s HTTP/1.1\r\n"
			"User-Agent: radare2 " R2_VERSION "\r\n"
			"Accept: */*\r\n"
			"Host: %s:%s\r\n"
			"\r\n",
			path, host, port);
		response = socket_http_answer (s, NULL, code, rlen, redirections);
	} else {
		R_LOG_ERROR ("Cannot connect to %s:%s", host, port);
		response = NULL;
	}
	free (uri);
	r_socket_free (s);
	return response;
#endif
}

R_API char *r_socket_http_get(const char *url, const char **headers, int *code, int *rlen) {
	return socket_http_get_recursive (url, headers, code, rlen, SOCKET_HTTP_MAX_REDIRECTS);
}

R_API bool r_socket_http_download(const char *url, const char **headers, const char *filepath) {
	int code, rlen;
	char *data = r_socket_http_get (url, headers, &code, &rlen);
	if (!data || code != 200) {
		if (code != 200) {
			R_LOG_ERROR ("HTTP download failed with status code %d", code);
		}
		free (data);
		return false;
	}
	bool ret = r_file_dump (filepath, (const ut8 *)data, rlen, false);
	free (data);
	return ret;
}

R_API char *r_socket_http_post(const char *url, const char *headers[], const char *data, int *code, int *rlen) {
	if (r_sys_getenv_asbool ("R2_CURL")) {
		int len;
		char *escaped_url = r_str_escape_sh (url);
		if (!escaped_url) {
			return NULL;
		}
		RStrBuf *sb = r_strbuf_new ("curl -s -D - -L");
		if (headers) {
			const char **header = headers;
			while (*header) {
				char *escaped_header = r_str_escape_sh (*header);
				r_strbuf_appendf (sb, " -H '%s'", escaped_header);
				free (escaped_header);
				header++;
			}
		}
		char *escaped_data = r_str_escape_sh (data);
		r_strbuf_appendf (sb, " -d \"%s\"", escaped_data);
		free (escaped_data);
		r_strbuf_appendf (sb, " \"%s\"", escaped_url);
		char *command = r_strbuf_drain (sb);

		char *error = NULL;
		char *res = NULL;

		// Execute curl command
		int cmd_result = r_sys_cmd_str_full (command, NULL, 0, &res, &len, &error);

		free (escaped_url);
		free (command);

		if (cmd_result <= 0 || !res) {
			// Command failed to execute
			if (code) {
				*code = 500; // Internal error
			}
			if (error && *error) {
				R_LOG_ERROR ("curl failed: %s", error);
				char *err_msg = strdup (error);
				free (error);
				free (res);
				return err_msg;
			} else {
				R_LOG_ERROR ("curl failed to execute");
				free (error);
				free (res);
				return NULL;
			}
		}

		// Parse the response
		if (res) {
			// Parse HTTP status code from header
			if (code) {
				char *status_line = strstr (res, "HTTP/");
				if (status_line) {
					char *space = strchr (status_line, ' ');
					if (space) {
						*code = atoi (space + 1);
					} else {
						*code = 200; // Default success
					}
				} else {
					*code = 200; // Default success
				}
			}

			// Separate headers from body
			char *body = strstr (res, "\r\n\r\n");
			if (body) {
				body += 4;
				// Move the body to the beginning of the string
				char *new_res = strdup (body);
				free (res);
				res = new_res;
			}

			free (error);
			if (rlen) {
				*rlen = strlen (res);
			}
		}

		return res;
	}
	bool ssl = r_str_startswith (url, "https://");
	char *uri = strdup (url);
	if (!uri) {
		return NULL;
	}

	char *host = strstr (uri, "://");
	if (!host) {
		free (uri);
		R_LOG_ERROR ("Invalid URI");
		return NULL;
	}
	host += 3;
	char *port = strchr (host, ':');
	char *path = strchr (host, '/');
	if (port && (!path || (path && port < path))) {
		*port++ = 0;
	} else {
		port = ssl? "443": "80";
	}
	if (path) {
		*path++ = 0;
	} else {
		path = "";
	}
	RSocket *s = r_socket_new (ssl);
	if (!s) {
		R_LOG_ERROR ("Cannot create socket");
		free (uri);
		return NULL;
	}
	if (!r_socket_connect_tcp (s, host, port, 0)) {
		R_LOG_ERROR ("Cannot connect to %s:%s", host, port);
		free (uri);
		r_socket_free (s);
		return NULL;
	}
	/* Send */
	// RStrBuf *sb = r_strbuf_new ("POST /%s HTTP/1.0\r\n");
	// char *data = r_strbuf_drain (sb);
	r_socket_printf (s,
		"POST /%s HTTP/1.0\r\n"
		"User-Agent: radare2 " R2_VERSION "\r\n"
		"Accept: */*\r\n"
		"Host: %s:%d\r\n"
		"Content-Length: %i\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"\r\n",
		path, host, atoi (port), (int)strlen (data));
	free (uri);
	r_socket_write (s, (void *)data, strlen (data));
	return socket_http_answer (s, NULL, code, rlen, 0);
}

#if TEST
void main() {
	int ret;
	char *p = r_socket_http_post ("https://www.radare.org/y/index.php", "a=b", &ret);
	printf ("%s\n", p);
}
#endif
