#ifndef R_ENDIAN_H
#define R_ENDIAN_H

/* Endian agnostic functions working on single byte. */

static inline ut8 r_read_ble8(const void *src) {
	return *(ut8 *)src;
}

static inline ut8 r_read_at_ble8(const void *src, size_t offset) {
	return r_read_ble8 (((const ut8*)src) + offset);
}

static inline void r_write_ble8(void *dest, ut8 val) {
	*(ut8 *)dest = val;
}

static inline void r_write_at_ble8(void *dest, ut8 val, size_t offset) {
	ut8 *d = (ut8*)dest + offset;
	r_write_ble8 (d, val);
}

/* Big Endian functions. */

static inline ut8 r_read_be8(const void *src) {
	return r_read_ble8 (src);
}

static inline ut8 r_read_at_be8(const void *src, size_t offset) {
	return r_read_at_ble8 (src, offset);
}

static inline void r_write_be8(void *dest, ut8 val) {
	r_write_ble8 (dest, val);
}

static inline void r_write_at_be8(void *dest, ut8 val, size_t offset) {
	r_write_at_ble8 (dest, val, offset);
}

static inline ut16 r_read_be16(const void *src) {
	const ut8 *s = (const ut8*)src;
	return (((ut16)s[0]) << 8) | (((ut16)s[1]) << 0);
}

static inline ut16 r_read_at_be16(const void *src, size_t offset) {
	const ut8 *s = (const ut8*)src + offset;
	return r_read_be16 (s);
}

static inline void r_write_be16(void *dest, ut16 val) {
	r_write_be8 (dest, val >> 8);
	r_write_at_be8 (dest, val >> 0, sizeof (ut8));
}

static inline void r_write_at_be16(void *dest, ut16 val, size_t offset) {
	ut8 *d = (ut8*)dest + offset;
	r_write_be16 (d, val);
}

static inline ut32 r_read_be32(const void *src) {
	const ut8 *s = (const ut8*)src;
	return (((ut32)s[0]) << 24) | (((ut32)s[1]) << 16) |
		(((ut32)s[2]) << 8) | (((ut32)s[3]) << 0);
}

static inline ut32 r_read_at_be32(const void *src, size_t offset) {
	const ut8 *s = (const ut8*)src + offset;
	return r_read_be32 (s);
}

static inline void r_write_be32(void *dest, ut32 val) {
	r_write_be16 (dest, val >> 16);
	r_write_at_be16 (dest, val >> 0, sizeof (ut16));
}

static inline void r_write_at_be32(void *dest, ut32 val, size_t offset) {
	ut8 *d = (ut8*)dest + offset;
	r_write_be32 (d, val);
}

static inline ut64 r_read_be64(const void *src) {
	ut64 val = ((ut64)(r_read_be32 (src))) << 32;
	val |= r_read_at_be32 (src, sizeof (ut32));
	return val;
}

static inline ut64 r_read_at_be64(const void *src, size_t offset) {
	const ut8 *s = (const ut8*)src + offset;
	return r_read_be64 (s);
}

static inline void r_write_be64(void *dest, ut64 val) {
	r_write_be32 (dest, val >> 32);
	r_write_at_be32 (dest, val >> 0, sizeof (ut32));
}

static inline void r_write_at_be64(void *dest, ut64 val, size_t offset) {
	ut8 *d = (ut8*)dest + offset;
	r_write_be64 (d, val);
}

/* Little Endian functions. */

static inline ut8 r_read_le8(const void *src) {
	return r_read_ble8 (src);
}

static inline ut8 r_read_at_le8(const void *src, size_t offset) {
	return r_read_at_ble8 (src, offset);
}

static inline void r_write_le8(void *dest, ut8 val) {
	r_write_ble8 (dest, val);
}

static inline void r_write_at_le8(void *dest, ut8 val, size_t offset) {
	r_write_at_ble8 (dest, val, offset);
}

static inline ut16 r_read_le16(const void *src) {
	const ut8 *s = (const ut8*)src;
	return (((ut16)s[1]) << 8) | (((ut16)s[0]) << 0);
}

static inline ut16 r_read_at_le16(const void *src, size_t offset) {
	const ut8 *s = (const ut8*)src + offset;
	return r_read_le16 (s);
}

static inline void r_write_le16(void *dest, ut16 val) {
	r_write_le8 (dest, val >> 0);
	r_write_at_le8 (dest, val >> 8, sizeof (ut8));
}

static inline void r_write_at_le16(void *dest, ut16 val, size_t offset) {
	ut8 *d = (ut8 *)dest + offset;
	r_write_le16 (d, val);
}

static inline ut32 r_read_le32(const void *src) {
	const ut8 *s = (const ut8*)src;
	return (((ut32)s[3]) << 24) | (((ut32)s[2]) << 16) |
		(((ut32)s[1]) << 8) | (((ut32)s[0]) << 0);
}

static inline ut32 r_read_at_le32(const void *src, size_t offset) {
	const ut8 *s = (const ut8*)src + offset;
	return r_read_le32 (s);
}

static inline void r_write_le32(void *dest, ut32 val) {
	r_write_le16 (dest, val >> 0);
	r_write_at_le16 (dest, val >> 16, sizeof (ut16));
}

static inline void r_write_at_le32(void *dest, ut32 val, size_t offset) {
	ut8 *d = ((ut8*)dest) + offset;
	r_write_le32 (d, val);
}

static inline ut64 r_read_le64(const void *src) {
	ut64 val = ((ut64)(r_read_at_le32 (src, sizeof (ut32)))) <<  32;
	val |= r_read_le32 (src);
	return val;
}

static inline ut64 r_read_at_le64(const void *src, size_t offset) {
	const ut8 *s = ((const ut8*)src) + offset;
	return r_read_le64 (s);
}

static inline void r_write_le64(void *dest, ut64 val) {
	r_write_le32 (dest, val >> 0);
	r_write_at_le32 (dest, val >> 32, sizeof (ut32));
}

static inline void r_write_at_le64(void *dest, ut64 val, size_t offset) {
	ut8 *d = (ut8*)dest + offset;
	r_write_le64 (d, val);
}

/* Helper functions */

static inline ut16 r_read_ble16(const void *src, bool big_endian) {
	return big_endian? r_read_be16 (src): r_read_le16 (src);
}

static inline ut32 r_read_ble32(const void *src, bool big_endian) {
	return big_endian? r_read_be32 (src): r_read_le32 (src);
}

static inline ut64 r_read_ble64(const void *src, bool big_endian) {
	return big_endian? r_read_be64 (src): r_read_le64 (src);
}

static inline void r_write_ble16(void *dest, ut16 val, bool big_endian) {
	big_endian? r_write_be16 (dest, val): r_write_le16 (dest, val);
}

static inline void r_write_ble32(void *dest, ut32 val, bool big_endian) {
	big_endian? r_write_be32 (dest, val): r_write_le32 (dest, val);
}

static inline void r_write_ble64(void *dest, ut64 val, bool big_endian) {
	big_endian? r_write_be64 (dest, val): r_write_le64 (dest, val);
}

#endif
