#include <stdio.h>
#include "code.h"
#include <sdb.h>

int main() {
	Sdb *kv = sdb_new(NULL, NULL, 0);
	RBinJavaObj *o = r_bin_java_new ("/tmp/CON.class", 0, kv);
	printf ("Hello World %p\n", o);
	return 0;
}
