/* radare - LGPL - Copyright 2012 - pancake */

#include <r_socket.h>

typedef struct r_socket_http_request {
	RSocket *s;
	char *path;
	char *host;
	char *agent;
	char *method;
	char *data;
} RSocketHTTPRequest;

static RSocketHTTPRequest *r_socket_http_accept (RSocket *s) {
	int pxx = 1, first = 0;
	char buf[1024], *p, *q;
	RSocketHTTPRequest *hr = R_NEW0 (RSocketHTTPRequest);
	hr->s = r_socket_accept (s);
	if (!hr->s) {
		free (hr);
		return NULL;
	}
	for (;;) {
		int xx = r_socket_gets (hr->s, buf, sizeof (buf));
		int yy = r_socket_ready (hr->s, 0, 20);
		eprintf ("READ %d (%s) READY %d\n", xx, buf, yy);
		if (yy == 0) {
			eprintf ("BREAK\n");
			break;
		}
		if (xx == 0 && pxx == 0) {
			eprintf ("BREAK LONG\n");
			break;
		}
		pxx = xx;
		
		if (first==0) {
			first = 1;
			p = strchr (buf, ' ');
			if (p) *p = 0;
			hr->method = strdup (buf);
			if (p) {
				q = strchr (p+1, ' ');
				if (q) *q = 0;
				hr->path = strdup (p+1);
			}
		}
	}
	eprintf ("RET\n");
	
	return hr;
}

static void r_socket_http_response (RSocketHTTPRequest *rs, int code, const char *out) {
	// HTTP/1.1 200 OK
	// headers
	// \n\n
	// body
	r_socket_puts (rs->s, "HTTP/1.1 200 OK\n\nHello World\n");
}

/* close client socket and free struct */
static void r_socket_http_close (RSocketHTTPRequest *rs) {
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
			// get method
			r_socket_http_response (rs, 200, "Fuck yeah");
			r_socket_http_close (rs);
		}
	}
}
#endif
