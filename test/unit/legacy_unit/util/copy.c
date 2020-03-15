#include <r_util.h>

#define F "/etc/services"

int main () {
	size_t len;
	char *out= r_file_slurp (F, &len);
	r_file_dump ("a", out, (int)len);
	system ("md5 "F);
	system ("md5 a");
	return 0;
}
