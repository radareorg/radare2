/*
  zip_source_function.c -- create zip data source from callback function
  Copyright (C) 1999-2022 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <info@libzip.org>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the
     distribution.
  3. The names of the authors may not be used to endorse or promote
     products derived from this software without specific prior
     written permission.

  THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
  IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
  IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#include <stdlib.h>

#include "zipint.h"


ZIP_EXTERN zip_source_t *
zip_source_function(zip_t *za, zip_source_callback zcb, void *ud) {
    if (za == NULL) {
        return NULL;
    }

    return zip_source_function_create(zcb, ud, &za->error);
}


ZIP_EXTERN zip_source_t *
zip_source_function_create(zip_source_callback zcb, void *ud, zip_error_t *error) {
    zip_source_t *zs;

    if ((zs = _zip_source_new(error)) == NULL)
        return NULL;

    zs->cb.f = zcb;
    zs->ud = ud;

    zs->supports = zcb(ud, NULL, 0, ZIP_SOURCE_SUPPORTS) | zip_source_make_command_bitmap(ZIP_SOURCE_SUPPORTS, -1);
    if (zs->supports < 0) {
        zs->supports = ZIP_SOURCE_SUPPORTS_READABLE;
    }

    return zs;
}


ZIP_EXTERN void
zip_source_keep(zip_source_t *src) {
    src->refcount++;
}


zip_source_t *
_zip_source_new(zip_error_t *error) {
    zip_source_t *src;

    if ((src = (zip_source_t *)malloc(sizeof(*src))) == NULL) {
        zip_error_set(error, ZIP_ER_MEMORY, 0);
        return NULL;
    }

    src->src = NULL;
    src->cb.f = NULL;
    src->ud = NULL;
    src->open_count = 0;
    src->write_state = ZIP_SOURCE_WRITE_CLOSED;
    src->source_closed = false;
    src->source_archive = NULL;
    src->refcount = 1;
    zip_error_init(&src->error);
    src->eof = false;
    src->had_read_error = false;
    src->bytes_read = 0;

    return src;
}
