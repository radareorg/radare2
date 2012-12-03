/* radare - LGPL - Copyright 2012 - pancake */

#include <r_socket.h>

R_API RSocketHTTPRequest *r_socket_http_accept (RSocket *s, int timeout) {
	int content_length = 0;
	int pxx = 1, first = 0;
	char buf[1024], *p, *q;
	RSocketHTTPRequest *hr = R_NEW0 (RSocketHTTPRequest);
	hr->s = r_socket_accept (s);
	if (!hr->s) {
		free (hr);
		return NULL;
	}
	eprintf ("timeout = %d\n", timeout);
	r_socket_block_time (hr->s, 1, timeout);
	for (;;) {
eprintf ("--\n");
		int xx = r_socket_gets (hr->s, buf, sizeof (buf));
		int yy = r_socket_ready (hr->s, 0, 20);
//		eprintf ("READ %d (%s) READY %d\n", xx, buf, yy);
		if (!yy || (!xx && !pxx))
			break;
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
				q = strchr (p+1, ' ');
				if (q) *q = 0;
				hr->path = strdup (p+1);
			}
		} else {
			if (!hr->agent && !memcmp (buf, "User-Agent: ", 12)) {
				hr->agent = strdup (buf+12);
			} else
			if (!hr->host && !memcmp (buf, "Host: ", 6)) {
				hr->host = strdup (buf+6);
			} else
			if (!memcmp (buf, "Content-Length: ", 16)) {
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
	r_socket_printf (rs->s, "HTTP/1.0 %d %s\n%s"
		"Content-Length: %d\n\n", code, strcode, headers, len);
	if (out && len>0) r_socket_write (rs->s, (void*)out, len);
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
		RSocketHTTPRequest *rs = r_socket_http_accept (s);
		if (!strcmp (rs->method, "GET")) {
			r_socket_http_response (rs, 200,
	"<html><body><form method=post action=/><input name=a /><input type=button></form></body>");
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
