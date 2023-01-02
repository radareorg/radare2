#ifndef _R_MD5_H
#define _R_MD5_H

void r_hash_md5_init(RHashMD5Context *);
void r_hash_md5_update(RHashMD5Context *, const ut8*, unsigned int);
void r_hash_md5_final(ut8 [16], RHashMD5Context *);

#endif
