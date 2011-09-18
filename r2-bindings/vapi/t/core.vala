using Radare;

public static void main(string[] args)
{
	var c = new RCore();
	var a = RDebug.ProcessStatus.STOP;
print ("VERSION: "+Radare.R2_VERSION+"\n");
	RCore.File *f = c.file_open("/bin/ls", 0);
	//stdout.printf("Filedescriptor: %d %d\n", f->fd->fd, a);
	c.cmd("x", true);
	c.cmd0("");
RCons.flush();
	c.cmd0(".");
	//c.cmd("x- 128 @ 33", false);
	RCons.flush();
}
