/*
  zip_source_zip_new.c -- prepare data structures for zip_fopen/zip_source_zip
  Copyright (C) 2012-2021 Dieter Baron and Thomas Klausner

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

static void _zip_file_attributes_from_dirent(zip_file_attributes_t *attributes, zip_dirent_t *de);

zip_source_t *_zip_source_zip_new(zip_t *srcza, zip_uint64_t srcidx, zip_flags_t flags, zip_uint64_t start, zip_uint64_t len, const char *password, zip_error_t *error) {
    zip_source_t *src, *s2;
    zip_stat_t st;
    zip_file_attributes_t attributes;
    zip_dirent_t *de;
    bool partial_data, needs_crc, needs_decrypt, needs_decompress;

    if (srcza == NULL || srcidx >= srcza->nentry || len > ZIP_INT64_MAX) {
        zip_error_set(error, ZIP_ER_INVAL, 0);
        return NULL;
    }

    if ((flags & ZIP_FL_UNCHANGED) == 0 && (ZIP_ENTRY_DATA_CHANGED(srcza->entry + srcidx) || srcza->entry[srcidx].deleted)) {
        zip_error_set(error, ZIP_ER_CHANGED, 0);
        return NULL;
    }

    if (zip_stat_index(srcza, srcidx, flags | ZIP_FL_UNCHANGED, &st) < 0) {
        zip_error_set(error, ZIP_ER_INTERNAL, 0);
        return NULL;
    }

    if (flags & ZIP_FL_ENCRYPTED) {
        flags |= ZIP_FL_COMPRESSED;
    }

    if ((start > 0 || len > 0) && (flags & ZIP_FL_COMPRESSED)) {
        zip_error_set(error, ZIP_ER_INVAL, 0);
        return NULL;
    }

    /* overflow or past end of file */
    if ((start > 0 || len > 0) && (start + len < start || start + len > st.size)) {
        zip_error_set(error, ZIP_ER_INVAL, 0);
        return NULL;
    }

    if (len == 0) {
        len = st.size - start;
    }

    partial_data = len < st.size;
    needs_decrypt = ((flags & ZIP_FL_ENCRYPTED) == 0) && (st.encryption_method != ZIP_EM_NONE);
    needs_decompress = ((flags & ZIP_FL_COMPRESSED) == 0) && (st.comp_method != ZIP_CM_STORE);
    /* when reading the whole file, check for CRC errors */
    needs_crc = ((flags & ZIP_FL_COMPRESSED) == 0 || st.comp_method == ZIP_CM_STORE) && !partial_data;

    if (needs_decrypt) {
        if (password == NULL) {
            password = srcza->default_password;
        }
        if (password == NULL) {
            zip_error_set(error, ZIP_ER_NOPASSWD, 0);
            return NULL;
        }
    }

    if ((de = _zip_get_dirent(srcza, srcidx, flags, error)) == NULL) {
        return NULL;
    }
    _zip_file_attributes_from_dirent(&attributes, de);

    if (st.comp_size == 0) {
        return zip_source_buffer_with_attributes_create(NULL, 0, 0, &attributes, error);
    }

    if (partial_data && !needs_decrypt && !needs_decompress) {
        struct zip_stat st2;

        st2.size = len;
        st2.comp_size = len;
        st2.comp_method = ZIP_CM_STORE;
        st2.mtime = st.mtime;
        st2.valid = ZIP_STAT_SIZE | ZIP_STAT_COMP_SIZE | ZIP_STAT_COMP_METHOD | ZIP_STAT_MTIME;

        if ((src = _zip_source_window_new(srcza->src, start, (zip_int64_t)len, &st2, &attributes, srcza, srcidx, error)) == NULL) {
            return NULL;
        }
    }
    else {
        if (st.comp_size > ZIP_INT64_MAX) {
            zip_error_set(error, ZIP_ER_INVAL, 0);
            return NULL;
        }
        if ((src =  _zip_source_window_new(srcza->src, 0, (zip_int64_t)st.comp_size, &st, &attributes, srcza, srcidx, error)) == NULL) {
            return NULL;
        }
    }

    if (_zip_source_set_source_archive(src, srcza) < 0) {
        zip_source_free(src);
        return NULL;
    }

    /* creating a layered source calls zip_keep() on the lower layer, so we free it */

    if (needs_decrypt) {
        zip_encryption_implementation enc_impl;

        if ((enc_impl = _zip_get_encryption_implementation(st.encryption_method, ZIP_CODEC_DECODE)) == NULL) {
            zip_error_set(error, ZIP_ER_ENCRNOTSUPP, 0);
            return NULL;
        }

        s2 = enc_impl(srcza, src, st.encryption_method, 0, password);
        zip_source_free(src);
        if (s2 == NULL) {
            return NULL;
        }
        src = s2;
    }
    if (needs_decompress) {
        s2 = zip_source_decompress(srcza, src, st.comp_method);
        zip_source_free(src);
        if (s2 == NULL) {
            return NULL;
        }
        src = s2;
    }
    if (needs_crc) {
        s2 = zip_source_crc_create(src, 1, error);
        zip_source_free(src);
        if (s2 == NULL) {
            return NULL;
        }
        src = s2;
    }

    if (partial_data && (needs_decrypt || needs_decompress)) {
        s2 = zip_source_window_create(src, start, (zip_int64_t)len, error);
        zip_source_free(src);
        if (s2 == NULL) {
            return NULL;
        }
        src = s2;
    }

    return src;
}

static void
_zip_file_attributes_from_dirent(zip_file_attributes_t *attributes, zip_dirent_t *de) {
    zip_file_attributes_init(attributes);
    attributes->valid = ZIP_FILE_ATTRIBUTES_ASCII | ZIP_FILE_ATTRIBUTES_HOST_SYSTEM | ZIP_FILE_ATTRIBUTES_EXTERNAL_FILE_ATTRIBUTES | ZIP_FILE_ATTRIBUTES_GENERAL_PURPOSE_BIT_FLAGS;
    attributes->ascii = de->int_attrib & 1;
    attributes->host_system = de->version_madeby >> 8;
    attributes->external_file_attributes = de->ext_attrib;
    attributes->general_purpose_bit_flags = de->bitflags;
    attributes->general_purpose_bit_mask = ZIP_FILE_ATTRIBUTES_GENERAL_PURPOSE_BIT_FLAGS_ALLOWED_MASK;
}
