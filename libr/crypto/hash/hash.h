int hash_par(unsigned char *buffer, ut64 len);
ut16 hash_xorpair(const ut8 *b, ut64 len);
ut8  hash_xor(const ut8 *b, ut64 len);
ut8  hash_mod255(const ut8 *b, ut64 len);
ut32 hash_wrt54gv5v6(const ut8 *pStart, ut64 len);
ut16 hash_bootp(const ut8 *data, ut64 len);
ut8  hash_hamdist(const ut8 *buf, ut64 len);
float hash_entropy(const ut8 *data, ut64 size);
int hash_pcprint(unsigned char *buffer, ut64 len);
float get_px(ut8 x, ut8 const *data, ut64 size);
ut16 crc16(ut16 crc, const ut8 *buffer, ut64 len);
void mdfour(ut8 *out, const ut8 *in, ut64 n);
ut32 crc32(ut8 *buf, ut64 len);

ut64 r_hash_name_to_bits(const char *name);
//extern ut16 const crc16_table[256];
