#include <r_util.h>
int main() {
    char *s = r_str_wrap("hello world\nhow are you\n", 5);
    printf("Result: '");
    for (char *p = s; *p; p++) {
        if (*p == '\n') printf("\\n");
        else if (*p == ' ') printf(" ");
        else putchar(*p);
    }
    printf("'\n");
    free(s);
    return 0;
}
