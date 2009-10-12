/* valac --profile=posix --pkg r_socket socket.vala */

using Radare;

public static void main()
{
	string str = (string) new char[4096];

	//var fd = Socket.connect("www.google.com", 80);
	var fd = Socket.connect("localhost", 9999);
	if (fd == -1) {
		printf("Cannot connect\n");
		return;
	}

	fd.printf("GET /\r\n\r\n");

	printf("[-] waiting for output\n");
	while(!fd.ready(0,0));

	printf("[-] reading data\n");
	while(fd.fgets(str, 1024)>0) {
		printf(str+"\n");
	}
	fd.close();
}
