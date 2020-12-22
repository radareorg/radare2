#ifndef R_ULEB128_H
#define R_ULEB128_H

// LEB128 or Little Endian Base 128 is a form of variable-length code
// compression used to store an arbitrarily large integer in a small number of
// bytes. LEB128 is used in the DWARF debug file format.

R_API const ut8 *r_uleb128(const ut8 *data, int datalen, ut64 *v, const char **error);
R_API const ut8 *r_uleb128_decode(const ut8 *data, int *datalen, ut64 *v);
R_API int r_uleb128_len(const ut8 *data, int size);
R_API ut8 *r_uleb128_encode(const ut64 s, int *len);
R_API const ut8 *r_leb128(const ut8 *data, int datalen, st64 *v);
R_API st64 r_sleb128(const ut8 **data, const ut8 *end);
R_API size_t read_u32_leb128(const ut8 *p, const ut8 *max, ut32 *out_val);
R_API size_t read_i32_leb128(const ut8 *p, const ut8 *max, st32 *out_val);
R_API size_t read_u64_leb128(const ut8 *p, const ut8 *max, ut64 *out_val);
R_API size_t read_i64_leb128(const ut8 *p, const ut8 *max, st64 *out_val);
#endif //  R_ULEB128_H
