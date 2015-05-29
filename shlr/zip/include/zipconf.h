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
#include <r_types_base.h>

typedef st8 zip_int8_t;
#define ZIP_INT8_MIN ST8_MIN
#define ZIP_INT8_MAX ST8_MAX

typedef ut8 zip_uint8_t;
#define ZIP_UINT8_MAX UT8_MAX

typedef st16 zip_int16_t;
#define ZIP_INT16_MIN ST16_MIN
#define ZIP_INT16_MAX ST16_MAX

typedef ut16 zip_uint16_t;
#define ZIP_UINT16_MAX UT16_MAX

typedef st32 zip_int32_t;
#define ZIP_INT32_MIN ST32_MIN
#define ZIP_INT32_MAX ST32_MAX

typedef ut32 zip_uint32_t;
#define ZIP_UINT32_MAX UT32_MAX

typedef st64 zip_int64_t;
#define ZIP_INT64_MIN ST64_MIN
#define ZIP_INT64_MAX ST64_MAX

typedef ut64 zip_uint64_t;
#define ZIP_UINT64_MAX UT64_MAX


#endif /* zipconf.h */
