using Radare;

void main(string[] args)
{
	var io = new Radare.rIo ();

	int fd = io.open ("dbg:///bin/ls", 0, 0); //Io.Flags.READ, 0);
	if (fd == -1)
		critical("Cannot open file\n");
	
	uint8 buf[16];
	io.read_at (0x8048000, buf, 10);
	print ("0x8048000 : %02x %02x %02x %02x\n",
		buf[0], buf[1], buf[2], buf[3]);
/*
	Radare.List<IO.Handle> handle = io.handlers;
	while (!handle->last()) {
		print(" Handle: %s\n", handle->name);
		handle = handle->next();
	}
	handle->free();
*/
}
