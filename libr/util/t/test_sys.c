#include <stdio.h>
#include "r_util.h"


int main(int argc, char *argv[]) {
       int len = 0;
       char *sterr;
       char *output = r_sys_cmd_str("find /etc", 0, &len);
       output = r_sys_cmd_str_full("find /etc", 0, &len, &sterr);
       printf("STDOUT\n");
       printf("%s", output);
       printf("STDERR\n");
       printf("%s", sterr);
       printf("bytes in STDOUT: %d\n", len);
       return 0;
}
