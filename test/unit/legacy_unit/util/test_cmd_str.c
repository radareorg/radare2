#include <r_util.h>

int main() {
	int out;
	printf ("%s\n", r_sys_cmd_str("less","hello world\nhow are you\n", &out));
	printf ("out=%d\n", out);
	return 0;
}
