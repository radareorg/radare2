/* test with server socket shellcode */
#include <stdio.h>

extern void process_syscall();

int main(int argc, char **argv)
{
	printf("Esperant rpc al port 8181...\n");
	process_syscall();
	return 0;
}
