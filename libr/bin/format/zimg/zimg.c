/* radare - LGPL - Copyright 2009-2015 - ninjahacker */

#include <r_types.h>
#include <r_util.h>
#include "zimg.h"


struct r_bin_zimg_obj_t* r_bin_zimg_new_buf(RBuffer *buf) {
	struct r_bin_zimg_obj_t *bin = R_NEW0 (struct r_bin_zimg_obj_t);
	if (!bin) {
		goto fail;
	}
	bin->size = buf->length;
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)){
		goto fail;
	}

	if (r_buf_size (bin->b) < sizeof (struct zimg_header_t)) {
		goto fail;
	}
	bin->header = (*(struct zimg_header_t*)bin->b->buf);

	return bin;

fail:
	if (bin) {
		r_buf_free (bin->b);
		free (bin);
	}
	return NULL;
}

