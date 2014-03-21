#ifndef __TMS320_P_H__
#define __TMS320_P_H__

#ifndef min
# define min(a,b)		((a) < (b) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))
#endif

#ifndef get_bits
# define get_bits(av, af, an)	(((av) >> (af)) & ((2 << (an - 1)) - 1))
#endif

static inline ut16 le16(ut16 v)
{
	ut16 value = v;
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
	ut8 * pv = (void *)&v;
	value = (pv[0] << 8) | pv[1];
#endif
	return value;
}

static inline ut32 le24(ut32 v)
{
	ut32 value = v;
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
	ut8 * pv = (void *)&v;
	value = (pv[0] << 16) | (pv[1] << 8) | pv[2];
#endif
	return value;
}

static inline ut32 le32(ut32 v)
{
	ut32 value = v;
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
	ut8 * pv = (void *)&v;
	value = (pv[0] << 24) | (pv[1] << 16) | (pv[2] << 8) | pv[3];
#endif
	return value;
}

static inline ut16 be16(ut16 v)
{
	ut16 value = v;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	ut8 * pv = (void *)&v;
	value = (pv[0] << 8) | pv[1];
#endif
	return value;
}

static inline ut32 be24(ut32 v)
{
	ut32 value = v;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	ut8 * pv = (void *)&v;
	value = (pv[0] << 16) | (pv[1] << 8) | pv[2];
#endif
	return value;
}

static inline ut32 be32(ut32 v)
{
	ut32 value = v;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	ut8 * pv = (void *)&v;
	value = (pv[0] << 24) | (pv[1] << 16) | (pv[2] << 8) | pv[3];
#endif
	return value;
}

#endif /* __TMS320_P_H__ */
