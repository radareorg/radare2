#ifndef R_ULEB128_H
#define R_ULEB128_H

// LEB128 or Little Endian Base 128 is a form of variable-length code
// compression used to store an arbitrarily large integer in a small number of
// bytes. LEB128 is used in the DWARF debug file format.

R_API const ut8 *r_uleb128(const ut8 *data, int datalen, ut64 *v);
R_API const ut8 *r_uleb128_decode(const ut8 *data, int *datalen, ut64 *v);
R_API const ut8 *r_uleb128_encode(const ut64 s, int *len);
R_API const ut8 *r_leb128(const ut8 *data, st64 *v);
#endif //  R_ULEB128_H
