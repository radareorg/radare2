using Radare;

public static void main(string[] args)
{
	var c = new RCore();
	var a = RDebug.ProcessStatus.STOP;
	RCore.File *f = c.file_open("/bin/ls", 0);
	stdout.printf("Filedescriptor: %d %d\n", f->fd, a);
	c.cmd("x- 128 @ 33", false);
	RCons.flush();
}
