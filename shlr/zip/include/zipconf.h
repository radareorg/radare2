#ifndef _HAD_ZIPCONF_H
#define _HAD_ZIPCONF_H

/*
   zipconf.h -- platform specific include file

   This file was generated automatically by ./make_zipconf.sh
   based on ../config.h.
 */

#define LIBZIP_VERSION "0.11.1"
#define LIBZIP_VERSION_MAJOR 0
#define LIBZIP_VERSION_MINOR 11
#define LIBZIP_VERSION_MICRO 0

#include <r_types.h>
#include <stdint.h>

typedef st8 zip_int8_t;
#define ZIP_INT8_MIN INT8_MIN
#define ZIP_INT8_MAX INT8_MAX

typedef ut8 zip_uint8_t;
#define ZIP_UINT8_MAX UINT8_MAX

typedef st16 zip_int16_t;
#define ZIP_INT16_MIN INT16_MIN
#define ZIP_INT16_MAX INT16_MAX

typedef ut16 zip_uint16_t;
#define ZIP_UINT16_MAX UINT16_MAX

typedef st32 zip_int32_t;
#define ZIP_INT32_MIN INT32_MIN
#define ZIP_INT32_MAX INT32_MAX

typedef ut32 zip_uint32_t;
#define ZIP_UINT32_MAX UINT32_MAX

typedef st64 zip_int64_t;
#define ZIP_INT64_MIN INT64_MIN
#define ZIP_INT64_MAX INT64_MAX

typedef ut64 zip_uint64_t;
#define ZIP_UINT64_MAX UINT64_MAX


#endif /* zipconf.h */
