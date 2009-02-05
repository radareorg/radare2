#include <stdio.h>
#include <string.h>
#include <r_cmd.h>

int cmd_quit(void *data, const char *input)
{
	printf("quit\n");
	exit(1);
}

int cmd_echo(void *data, const char *input)
{
	const char *arg = strchr(input, ' ');
	if (arg == NULL)
		arg = input;
	printf("%s\n", arg+1);
}

int main()
{
	struct r_cmd_t cmd;

	r_cmd_init(&cmd);

	r_cmd_add(&cmd, "e", "echo message", &cmd_echo);
	r_cmd_add(&cmd, "q", "quit program", &cmd_quit);

	r_cmd_add_long(&cmd, "echo", "e", "echo message");
	r_cmd_add_long(&cmd, "exit", "q", "quit program");

	r_cmd_call(&cmd, "e hello world short");
	r_cmd_call_long(&cmd, "echo hello world long");
	r_cmd_call_long(&cmd, "exit");
	r_cmd_call(&cmd, "quit");
}
