#ifndef R_UUID_HASH_H
#define R_UUID_HASH_H

#include <r_types.h>

/* Small self-contained SHA-1 and MD5, used only for UUID v3/v5 and for
 * mixing extra entropy. Inside the r2 tree these two files can be replaced
 * by calls to r_hash; they are kept here so that the UUID code is testable
 * on its own against RFC vectors. Not meant for anything security-critical. */

typedef struct {
	ut32 h[5];
	ut64 total;
	ut8 buf[64];
	size_t n;
} RUuidSha1;

typedef struct {
	ut32 h[4];
	ut64 total;
	ut8 buf[64];
	size_t n;
} RUuidMd5;

void r_uuid_sha1_init(RUuidSha1 *c);
void r_uuid_sha1_update(RUuidSha1 *c, const ut8 *data, size_t len);
void r_uuid_sha1_final(RUuidSha1 *c, ut8 out[20]);

void r_uuid_md5_init(RUuidMd5 *c);
void r_uuid_md5_update(RUuidMd5 *c, const ut8 *data, size_t len);
void r_uuid_md5_final(RUuidMd5 *c, ut8 out[16]);

#endif
