#ifndef _HAD_ZIPCONF_H
#define _HAD_ZIPCONF_H

/*
   zipconf.h -- platform specific include file

   This file was generated automatically by ./make_zipconf.sh
   based on ../config.h.
 */

#define LIBZIP_VERSION "1.11.4"
#define LIBZIP_VERSION_MAJOR 1
#define LIBZIP_VERSION_MINOR 11
#define LIBZIP_VERSION_MICRO 4

#define ZIP_STATIC 1

#include <stdint.h>

typedef int8_t zip_int8_t;
#define ZIP_INT8_MAX 0x7F
#define ZIP_INT8_MIN (-ZIP_INT8_MAX - 1)

typedef uint8_t zip_uint8_t;
#define ZIP_UINT8_MAX 0xFFU

typedef int16_t zip_int16_t;
#define ZIP_INT16_MAX 0x7FFF
#define ZIP_INT16_MIN (-ZIP_INT16_MAX - 1)

typedef uint16_t zip_uint16_t;
#define ZIP_UINT16_MAX 0xFFFFU

typedef int32_t zip_int32_t;
#define ZIP_INT32_MAX 0x7FFFFFFF
#define ZIP_INT32_MIN (-ZIP_INT32_MAX - 1)

typedef uint32_t zip_uint32_t;
#define ZIP_UINT32_MAX 0xFFFFFFFFU

typedef int64_t zip_int64_t;
#define ZIP_INT64_MAX 0x7FFFFFFFFFFFFFFFULL
#define ZIP_INT64_MIN (-ZIP_INT64_MAX - 1)

typedef uint64_t zip_uint64_t;
#define ZIP_UINT64_MAX 0xFFFFFFFFFFFFFFFFULL

#endif /* zipconf.h */
