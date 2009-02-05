using Radare;

public class SocketExample
{
	public static void main(string[] args)
	{
		unowned string str = new StringBuilder.sized(4096).str;
		//int fd = Socket.connect("www.google.com", 80);
		int fd = Socket.connect("localhost", 9999);

		Socket.printf(fd, "GET /\r\n\r\n");

		while(!Socket.ready(fd,0,0));
		stdout.printf("ready for data\n");

		while(Socket.fgets(fd, str, 1024)>0) {
			stdout.printf(str+"\n");
		}
		Socket.close(fd);
	}
}
