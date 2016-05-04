#include <r_socket.h>
#include "r_lib.h"
#include "r_core.h"
#include <string.h>
#include "r_io.h"

#define ENDIAN (0)
#define SERVER "127.0.0.1"
#define RMT_OPEN 0x01
#define RMT_READ 0x02
#define RMT_REPLY  0x80


int main (int argc, char ** argv) {
	char *PORT = "9999";
	RSocketRapServer *s = r_socket_rap_server_new (R_FALSE, (char *) PORT);
	if (s == NULL) {
		fprintf (stderr, "Error, cannot create new socket \n");
		return 1;
	}
	if (!r_socket_rap_server_listen(s, NULL)) {
		fprintf (stderr, "Error, Cannot listen on %d\n",(int) PORT);
		return 1;
	}

	RSocket *Client = r_socket_rap_server_accept(s);
	RSocketRapServer *ClServer = r_socket_rap_server_from_rsocket(R_FALSE, PORT, Client);
	char buf[1024];
	char tmp[1024];
	r_socket_read_block(Client, (ut8*) buf, 3);
	printf("%d\n", buf[0]);
	printf("%d\n", buf[1]);
	printf("%d\n", buf[2]);


	if(buf[0]== (char)(RMT_OPEN)){
		r_socket_read_block(Client, (ut8*) buf, buf[2]);
		printf("%s\n", (char *)buf);

		ut8 open[6];
		open[0] = RMT_OPEN|RMT_REPLY;
		open[1] = open[2] = open[3] = open[4] = 1;
		open[5] = 0;
		r_socket_rap_server_write(ClServer, (char *)open);

		for(int i=0;i<100;i++)
		{
			printf("%d\n", i);
			r_socket_rap_server_write(ClServer, (char *)open);
		}

		int ret = r_socket_read_block(Client, (ut8*)tmp, 1024);
		printf("%d %s\n", ret, tmp);
		if(ret==5)
		{
			int count =0;
			tmp[0] = RMT_READ|RMT_REPLY;
			tmp[1] = 1;
			tmp[2] = 1;
			tmp[3] = 1;
			tmp[4] = 1;
			tmp[5] = 0;

			r_socket_rap_server_write (ClServer, tmp);
		}
		//r_socket_rap_server_write(ClServer ,cmd);
	}
	return 0;
}