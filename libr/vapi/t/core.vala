using Radare;

public static void main(string[] args)
{
	var c = new rCore();
	rCore.File *f = c.file_open("/bin/ls", 0);
	stdout.printf("Filedescriptor: %d\n", f->fd);
	c.cmd("x- 128 @ 33", false);
	rCons.flush();
}
