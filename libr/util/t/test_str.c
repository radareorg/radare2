#include <stdio.h>
#include "r_util.h"


int main(int argc, char *argv[]) {
	char head[] =" a";
	char tail[] ="a ";
	char both[] =" a ";
	printf("r_str_trim_head('%s',): '%s'\n", " a", r_str_trim_head(head));fflush(stdout);	
	printf("r_str_trim_tail('%s',): '%s'\n", "a ", r_str_trim_tail(tail));fflush(stdout);
	printf("r_str_trim_head_tail('%s',): '%s'\n", " a ", r_str_trim_head_tail(both));fflush(stdout);	
	return 0;
}
