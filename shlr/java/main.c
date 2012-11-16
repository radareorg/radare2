#include <stdio.h>
#include "code.h"

int main() {
	RBinJavaObj *o = r_bin_java_new ("/tmp/CON.class");
	printf ("Hello World %p\n", o);
}
