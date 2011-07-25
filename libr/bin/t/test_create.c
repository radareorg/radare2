#include <r_bin.h>

int main () {
#define _BUFFER_SIZE 64
	unsigned char code[64] = {
		0x31, 0xc0, 0x40, 0x68, 0x2a, 0x00, 0x00, 0x00, 0x81, 0xec, 0x04, 
		0x00, 0x00, 0x00, 0xcd, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	RBuffer *b;
	RBin *bin = r_bin_new ();
	if (!r_bin_use_arch (bin, "x86", 32, "mach0")) {
		eprintf ("Cannot set arch\n");
		return 1;
	}
	b = r_bin_create (bin, code, _BUFFER_SIZE, NULL, 0);
	if (b) {
		if (r_file_dump ("a.out", b->buf, b->length))
			eprintf ("dumped %d bytes in a.out\n", b->length);
		else eprintf ("error dumping into a.out\n");
	} else eprintf ("So fucking oops\n");
	r_bin_free (bin);
	r_buf_free (b);
}
