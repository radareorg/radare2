/* radare - LGPL - Copyright 2026 - pancake */

#if R2__UNIX__ && !__wasi__ && !R2_UEFI

#define HTTP_FSCMD_MAX_REQUEST (2 * 1024 * 1024)
#define HTTP_FSCMD_MAX_BODY (16 * 1024 * 1024)
#define HTTP_FSCMD_MAX_REPLY (((HTTP_FSCMD_MAX_BODY + 2) / 3) * 4 + 1024)

static bool http_fscmd_url_valid(const char *url) {
	if (!url || (!r_str_startswith (url, "http://") && !r_str_startswith (url, "https://"))) {
		return false;
	}
	const char *host = strstr (url, "://") + 3;
	size_t hostlen = strcspn (host, "/?");
	if (!hostlen || memchr (host, '@', hostlen)) {
		return false;
	}
	const ut8 *p;
	for (p = (const ut8 *)url; *p; p++) {
		if (*p <= ' ' || *p == 127 || *p == '\\' || *p == '"' || *p == '#') {
			return false;
		}
	}
	return true;
}

static char *http_fscmd_payload(bool post, const char *url, const char **headers, const char *data, const char *upstream, const char *token) {
	if (!http_fscmd_url_valid (url) || !http_fscmd_url_valid (upstream) || strchr (upstream, '?')) {
		R_LOG_ERROR ("HTTP relay requires valid HTTP(S) URLs and an upstream base without a query");
		return NULL;
	}
	size_t baselen = strlen (upstream);
	while (upstream[baselen - 1] == '/') {
		baselen--;
	}
	if (strncmp (url, upstream, baselen) || (url[baselen] && url[baselen] != '/' && url[baselen] != '?')) {
		R_LOG_ERROR ("HTTP request does not match R2_HTTP_UPSTREAM");
		return NULL;
	}
	const char *suffix = url + baselen;
	char *path = *suffix == '/'? strdup (suffix): r_str_newf ("/%s", suffix);
	if (!path) {
		return NULL;
	}
	RStrBuf fields = {0};
	char *payload = NULL;
	if (strlen (path) > HTTP_FSCMD_MAX_REQUEST || strlen (token) > HTTP_FSCMD_MAX_REQUEST
			|| (data && strlen (data) > HTTP_FSCMD_MAX_REQUEST)) {
		goto beach;
	}
	if (headers) {
		const char **header;
		for (header = headers; *header; header++) {
			if (!**header) {
				continue;
			}
			size_t len = strlen (*header);
			if (len >= HTTP_FSCMD_MAX_REQUEST - r_strbuf_length (&fields)
					|| !r_strbuf_appendf (&fields, "%s\n", *header)) {
				goto beach;
			}
		}
	}
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "token", token);
	pj_ks (pj, "method", post? "POST": "GET");
	pj_ks (pj, "path", path);
	pj_ks (pj, "headers", r_strbuf_get (&fields));
	pj_ks (pj, "data", data? data: "");
	pj_end (pj);
	payload = pj_drain (pj);
	if (payload && strlen (payload) > HTTP_FSCMD_MAX_REQUEST) {
		R_FREE (payload);
	}
beach:
	if (!payload) {
		R_LOG_ERROR ("Cannot encode HTTP relay request within the 2 MiB limit");
	}
	free (path);
	r_strbuf_fini (&fields);
	return payload;
}

static bool http_fscmd_wait(int fd, int timeout) {
	ut64 start = r_time_now_mono ();
	while (r_time_now_mono () - start < (ut64)timeout * 1000000) {
		ut8 result[4];
		int size = r_sandbox_read (fd, result, sizeof (result));
		if (size == sizeof (result)) {
			st32 status = (st32)r_read_le32 (result);
			if (status) {
				R_LOG_ERROR ("HTTP relay transport failed (%d)", status);
			}
			return !status;
		}
		if (size > 0 || (size < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
			R_LOG_ERROR ("Cannot read HTTP relay completion");
			return false;
		}
		// TinyEMU returns zero bytes while the browser XHR is pending.
		r_sys_usleep (10000);
	}
	R_LOG_ERROR ("HTTP relay timed out");
	return false;
}

static char *http_fscmd_response(const char *file, int *code, int *rlen) {
	char *response = NULL;
	RJson *json = NULL;
	ut64 size = r_file_size (file);
	if (!size || size > HTTP_FSCMD_MAX_REPLY) {
		goto beach;
	}
	int length = 0;
	char *text = r_file_slurp_range (file, 0, (int)size, &length);
	if (text && length == size) {
		json = r_json_parsedup (text);
	}
	free (text);
	if (!json || json->type != R_JSON_OBJECT) {
		goto beach;
	}
	const RJson *status = r_json_get (json, "status");
	const char *body = r_json_get_str (json, "body");
	const char *encoding = r_json_get_str (json, "encoding");
	if (status && status->type == R_JSON_INTEGER
			&& status->num.s_value >= 100 && status->num.s_value <= 599
			&& body && encoding && !strcmp (encoding, "base64")) {
		response = (char *)r_base64_decode_dyn (body, -1, &length, true);
		if (length > HTTP_FSCMD_MAX_BODY) {
			R_FREE (response);
		}
		if (response) {
			if (code) {
				*code = status->num.s_value;
			}
			if (rlen) {
				*rlen = length;
			}
		}
	}
beach:
	if (!response) {
		R_LOG_ERROR ("Invalid HTTP relay response envelope");
	}
	r_json_free (json);
	return response;
}
#endif

static bool socket_http_fscmd(bool post, const char *url, const char **headers, const char *data, int *code, int *rlen, char **response) {
	char *relay = r_sys_getenv ("R2_HTTP_RELAY");
	if (R_STR_ISEMPTY (relay)) {
		free (relay);
		return false;
	}
	*response = NULL;
#if R2__UNIX__ && !__wasi__ && !R2_UEFI
	char *upstream = r_sys_getenv ("R2_HTTP_UPSTREAM");
	char *token = r_sys_getenv ("R2_HTTP_TOKEN");
	char *root = r_sys_getenv ("R2_HTTP_FS");
	char *payload = NULL, *directory = NULL, *request = NULL, *reply = NULL, *command = NULL;
	int fd = -1;
	bool created = false;
	if (r_sandbox_enable (false)) {
		R_LOG_ERROR ("sandbox: HTTP filesystem relay denied");
		goto beach;
	}
	if (!http_fscmd_url_valid (relay) || strlen (relay) >= 1024) {
		R_LOG_ERROR ("Invalid R2_HTTP_RELAY URL");
		goto beach;
	}
	if (R_STR_ISEMPTY (upstream) || R_STR_ISEMPTY (token)) {
		R_LOG_ERROR ("HTTP relay requires R2_HTTP_UPSTREAM and R2_HTTP_TOKEN");
		goto beach;
	}
	payload = http_fscmd_payload (post, url, headers, data, upstream, token);
	if (!payload) {
		goto beach;
	}
	const char *mount = R_STR_ISEMPTY (root)? "/mnt": root;
	directory = r_str_newf ("%s/tmp/r2-http-XXXXXX", mount);
	char *control = r_str_newf ("%s/.fscmd", mount);
	if (control) {
		fd = r_sandbox_open (control, O_RDWR | O_NONBLOCK, 0);
	}
	free (control);
	if (fd < 0 || !directory || !mkdtemp (directory)) {
		R_LOG_ERROR ("Cannot open HTTP relay filesystem at %s", mount);
		goto beach;
	}
	created = true;
	request = r_str_newf ("%s/request", directory);
	reply = r_str_newf ("%s/reply", directory);
	if (!request || !reply || !r_file_dump (request, (const ut8 *)payload, strlen (payload), false)) {
		goto beach;
	}
	// XHR filenames are relative to the 9p root, not the guest's root filesystem.
	const char *relative = directory + strlen (mount) + 1;
	command = r_str_newf ("xhr \"%s\" \"\" \"\" %s/request %s/reply \"\" 0\n", relay, relative, relative);
	if (!command || r_sandbox_write (fd, (const ut8 *)command, strlen (command)) != strlen (command)) {
		R_LOG_ERROR ("Cannot start HTTP relay request");
		goto beach;
	}
	int timeout = r_sys_getenv_asint ("R2_HTTP_TIMEOUT");
	if (http_fscmd_wait (fd, timeout > 0? timeout: 130)) {
		*response = http_fscmd_response (reply, code, rlen);
	}
beach:
	if (fd >= 0) {
		r_sandbox_close (fd);
	}
	if (created) {
		if (request) {
			r_file_rm (request);
		}
		if (reply) {
			r_file_rm (reply);
		}
		r_file_rm (directory);
	}
	free (command);
	free (reply);
	free (request);
	free (directory);
	free (payload);
	free (root);
	free (token);
	free (upstream);
#else
	R_LOG_ERROR ("HTTP filesystem relay is not supported on this platform");
#endif
	free (relay);
	return true;
}
