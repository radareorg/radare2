#include <r_types.h>
#include <r_util.h>
#include "dex.h"

char* r_bin_dex_get_version(struct r_bin_dex_obj_t* bin) {
	char *version = malloc (8);

	memset (version, 0, 8);
	memcpy (version, bin->b->buf+4, 3);
	return version;
}

struct r_bin_dex_obj_t* r_bin_dex_new_buf(struct r_buf_t *buf) {
	struct r_bin_dex_obj_t *bin;

	if (!(bin = malloc (sizeof (struct r_bin_dex_obj_t))))
		return NULL;
	memset (bin, 0, sizeof (struct r_bin_dex_obj_t));
	bin->b = buf;
	bin->size = buf->length;
	r_buf_read_at(bin->b, 0, (ut8*)&bin->header, sizeof (struct dex_header_t));
	return bin;
}

// Move to r_util ??
int dex_read_uleb128 (const char *ptr) {
    int cur, result = *(ptr++);

    if (result > 0x7f) {
        cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur > 0x7f) {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur > 0x7f) {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur > 0x7f) {
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }
    return result;
}

#define SIG_EXTEND(X,Y) X = (X << Y) >> Y
int dex_read_sleb128 (const char *ptr) {
    int cur, result = *(ptr++);

    if (result <= 0x7f) {
		SIG_EXTEND (result, 25);
    } else {
        cur = *(ptr++);
        result = (result & 0x7f) | ((cur & 0x7f) << 7);
        if (cur <= 0x7f) {
			SIG_EXTEND (result, 18);
        } else {
            cur = *(ptr++);
            result |= (cur & 0x7f) << 14;
            if (cur <= 0x7f) {
				SIG_EXTEND (result, 11);
            } else {
                cur = *(ptr++);
                result |= (cur & 0x7f) << 21;
                if (cur <= 0x7f) {
					SIG_EXTEND (result, 4);
                } else {
                    cur = *(ptr++);
                    result |= cur << 28;
                }
            }
        }
    }
    return result;
}
