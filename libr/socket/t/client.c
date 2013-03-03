#include <r_socket.h>

int main() {
	int ret;
	char buf[1024];
	RSocket *s = r_socket_new (R_FALSE);
	if (r_socket_connect (s, "localhost", "9090", 0, 10)) {
		do {
			ret = r_socket_gets (s, buf, sizeof (buf));
			eprintf ("((%s))\n", buf);
		} while (ret>=0);
	}
	r_socket_free (s);
}
