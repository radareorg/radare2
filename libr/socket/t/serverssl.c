#include <r_socket.h>
#define MAX_LINE 2048
#define PORT "4433"

int main (int argc, char ** argv) {
	char buf [MAX_LINE+1];
	RSocket *s, *cli;

	if (argc < 2) {
		eprintf ("Use %s <cert>\n", argv[0]);
		return 1;
	}
	s = r_socket_listen (PORT, 1, argv[1]);
	if (s == NULL) {
		eprintf ("Error, cant listen at port: %s\n", PORT);
		return 1;
	}
	while (1) {
		if (!(cli = r_socket_accept (s)))
			break;
		r_socket_read (cli, (unsigned char *)buf, 9);
		strcpy (buf, "HTTP/1.0 200 OK\r\n"
				"Server: EKRServer\r\n\r\n"
				"Server test page\r\n");
		r_socket_write (cli, buf, strlen (buf));
		r_socket_flush (cli);
		r_socket_free (cli);
	}
	r_socket_free (s);
	return 0;
}
