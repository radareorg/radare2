using Radare;

void main(string[] args)
{
	var io = new Radare.Io ();

	int fd = io.open ("dbg:///bin/ls", 0,0); //Io.Flags.READ, 0);
	if (fd != -1)
		critical("Cannot open file\n");
/*
	Radare.List<IO.Handle> handle = io.handlers;
	while (!handle->last()) {
		print(" Handle: %s\n", handle->name);
		handle = handle->next();
	}
	handle->free();
*/
}
