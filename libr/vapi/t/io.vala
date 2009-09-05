using Radare;

void main(string[] args)
{
	var io = new Radare.Io ();
	int fd = io.open ("/bin/ls", 0,0); //Io.Flags.READ, 0);
	if (fd != -1) {
		stdout.printf("cannot open file\n");
	}
/*
	Radare.Iter<IO.list> handle = io.handle_list();
	while (!handle->last()) {
		stdout.printf(" Handle: %s\n", handle->name);
		handle = handle->next();
	}
	handle->free();
*/
}
