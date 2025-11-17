#include <r_socket.h>

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
