/* radare - LGPL - Copyright 2012-2014 - pancake */

#include <r_socket.h>

R_API RSocketHTTPRequest *r_socket_http_accept (RSocket *s, int timeout) {
	int content_length = 0, xx, yy;
	int pxx = 1, first = 0;
	char buf[1500], *p, *q;
	RSocketHTTPRequest *hr = R_NEW0 (RSocketHTTPRequest);
	hr->s = r_socket_accept (s);
	if (!hr->s) {
		free (hr);
		return NULL;
	}
	if (timeout>0)
		r_socket_block_time (hr->s, 1, timeout);
	for (;;) {
		memset (buf, 0, sizeof (buf));
		xx = r_socket_gets (hr->s, buf, sizeof (buf));
		yy = r_socket_ready (hr->s, 0, 20 * 1000); //this function uses usecs as argument
//		eprintf ("READ %d (%s) READY %d\n", xx, buf, yy);
		if (!yy || (!xx && !pxx)) {
			break;
		}
		pxx = xx;
		
		if (first==0) {
			first = 1;
			if (strlen (buf)<3) {
				r_socket_http_close (hr);
				return NULL;
			}
			p = strchr (buf, ' ');
			if (p) *p = 0;
			hr->method = strdup (buf);
			if (p) {
				q = strstr (p+1, " HTTP"); //strchr (p+1, ' ');
				if (q) *q = 0;
				hr->path = strdup (p+1);
			}
		} else {
			if (!hr->agent && !strncmp (buf, "User-Agent: ", 12)) {
				hr->agent = strdup (buf+12);
			} else
			if (!hr->host && !strncmp (buf, "Host: ", 6)) {
				hr->host = strdup (buf+6);
			} else
			if (!strncmp (buf, "Content-Length: ", 16)) {
				content_length = atoi (buf+16);
			}
		}
	}
	if (content_length>0) {
		r_socket_read_block (hr->s, (ut8*)buf, 1); // one missing byte wtf
		hr->data = malloc (content_length+1);
		hr->data_length = content_length;
		r_socket_read_block (hr->s, hr->data, hr->data_length);
		hr->data[content_length] = 0;
	}
	return hr;
}

R_API void r_socket_http_response (RSocketHTTPRequest *rs, int code, const char *out, int len, const char *headers) {
	const char *strcode = \
		code==200?"ok":
		code==301?"moved permanently":
		code==302?"Found":
		code==404?"not found":
		"UNKNOWN";
	if (len<1) len = out? strlen (out): 0;
	if (!headers) headers = "";
	r_socket_printf (rs->s, "HTTP/1.0 %d %s\r\n%s"
		"Connection: close\r\nContent-Length: %d\r\n\r\n",
		code, strcode, headers, len);
	if (out && len>0) r_socket_write (rs->s, (void*)out, len);
}

R_API ut8 *r_socket_http_handle_upload(const ut8 *str, int len, int *retlen) {
	if (retlen)
		*retlen = 0;
	if (!strncmp ((const char *)str, "------------------------------", 10)) {
		int datalen;
		char *ret;
		const char *data, *token = (const char *)str+10;
		const char *end = strchr (token, '\n');
		if (!end)
			return NULL;
		data = strstr (end, "Content-Disposition: form-data; ");
		if (data) {
			data = strchr (data, '\n');
			if (data) data = strchr (data+1, '\n');
		}
		if (data) {
			while (*data==10 || *data==13) data++;
			end = (const char *)str+len-40;
			while (*end=='-') end--;
			if (*end==10 || *end==13) end--;
			datalen = (size_t)(end-data);
			ret = malloc (datalen+1);
			if (!ret) return NULL;
			memcpy (ret, data, datalen);
			ret[datalen] = 0;
			if (retlen)
				*retlen = datalen;
			return (ut8*)ret;
		}
	}
	return NULL;
}

/* close client socket and free struct */
R_API void r_socket_http_close (RSocketHTTPRequest *rs) {
	r_socket_free (rs->s);
	free (rs->path);
	free (rs->host);
	free (rs->agent);
	free (rs->method);
	free (rs->data);
	free (rs);
}

#if MAIN
int main() {
	RSocket *s = r_socket_new (R_FALSE);
	if (!r_socket_listen (s, "8080", NULL)) {
		eprintf ("Cannot listen here\n");
		return 1;
	}
	for (;;) {
		RSocketHTTPRequest *rs = r_socket_http_accept (s, 0);
		if (!rs) continue;
		if (!strcmp (rs->method, "GET")) {
			r_socket_http_response (rs, 200,
			"<html><body><form method=post action=/>"
			"<input name=a /><input type=button></form></body>");
		} else 
		if (!strcmp (rs->method, "POST")) {
			char *buf = malloc (rs->data_length+ 50);
			strcpy (buf, "<html><body><h2>XSS test</h2>\n");
			r_str_unescape (rs->data);
			strcat (buf, rs->data);
			r_socket_http_response (rs, 200, buf);
			free (buf);
		} else {
			r_socket_http_response (rs, 404, "Invalid protocol");
		}
		r_socket_http_close (rs);
	}
}
#endif
