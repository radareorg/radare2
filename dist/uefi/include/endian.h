/* radare2 uefi libc - LGPL - Copyright 2026 - pancake */

#ifndef _ENDIAN_H
#define _ENDIAN_H

#define __LITTLE_ENDIAN 1234
#define __BIG_ENDIAN 4321
#define __PDP_ENDIAN 3412
#define __BYTE_ORDER __LITTLE_ENDIAN

#define LITTLE_ENDIAN __LITTLE_ENDIAN
#define BIG_ENDIAN __BIG_ENDIAN
#define PDP_ENDIAN __PDP_ENDIAN
#define BYTE_ORDER __BYTE_ORDER

#define htobe16(x) __builtin_bswap16 (x)
#define htole16(x) (x)
#define be16toh(x) __builtin_bswap16 (x)
#define le16toh(x) (x)
#define htobe32(x) __builtin_bswap32 (x)
#define htole32(x) (x)
#define be32toh(x) __builtin_bswap32 (x)
#define le32toh(x) (x)
#define htobe64(x) __builtin_bswap64 (x)
#define htole64(x) (x)
#define be64toh(x) __builtin_bswap64 (x)
#define le64toh(x) (x)

#endif /* _ENDIAN_H */
