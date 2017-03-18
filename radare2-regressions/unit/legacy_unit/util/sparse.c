/* sparse test case */
#include <r_util.h> 

int main() {
	ut8 data[128];
	RBuffer *b = r_buf_new_sparse ();
	r_buf_write_at (b, 0x100, (void*)"Hello World", 12);
	r_buf_write_at (b, 0x200, (void*)"This Rocks!", 12);
	r_buf_write_at (b, 0x102, (void*)"XX", 2);
	r_buf_read_at (b, 0x101, data, 12);
	eprintf ("--> (%s)\n", data);
	r_buf_free (b);
	if (!strcmp ((const char *)data, "eXXo World")) {
		eprintf ("OK\n");
	} else {
		eprintf ("FAIL\n");
	}
	return 0;
}
