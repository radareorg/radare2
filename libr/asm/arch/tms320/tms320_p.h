#ifndef __TMS320_P_H__
#define __TMS320_P_H__

#ifndef get_bits
# define get_bits(av, af, an)	(((av) >> (af)) & ((2 << (an - 1)) - 1))
#endif

static inline ut32 le24(ut32 v) {
	ut32 value = v;
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
	ut8 * pv = (void *)&v;
	value = (pv[0] << 16) | (pv[1] << 8) | pv[2];
#endif
	return value;
}

static inline ut16 be16(ut16 v) {
	return ((v & 0xff) << 8) | (v >> 8);
}

static inline ut32 be24(ut32 v) {
	return ((v & 0xff) << 16) | (v & 0xff00) | ((v & 0xff0000) >> 16);
}

#endif /* __TMS320_P_H__ */
