/* radare - LGPL - Copyright 2009-2015 - ninjahacker */

#include <r_types.h>
#include <r_util.h>
#include "zimg.h"


struct r_bin_zimg_obj_t* r_bin_zimg_new_buf(RBuffer *buf) {
	struct r_bin_zimg_obj_t *bin = R_NEW0 (struct r_bin_zimg_obj_t);
	if (!bin) {
		goto fail;
	}
	bin->size = r_buf_size (buf);
	bin->b = r_buf_ref (buf);
	if (r_buf_size (bin->b) < sizeof (struct zimg_header_t)) {
		goto fail;
	}
	r_buf_read_at (bin->b, 0, (ut8 *)&bin->header, sizeof (bin->header));
	return bin;

fail:
	if (bin) {
		r_buf_free (bin->b);
		free (bin);
	}
	return NULL;
}

