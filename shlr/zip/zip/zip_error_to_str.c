/*
  zip_error_to_str.c -- get string representation of zip error code
  Copyright (C) 1999-2021 Dieter Baron and Thomas Klausner

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


#include <stdio.h>
#include <string.h>
#include <zlib.h>

#define _ZIP_COMPILING_DEPRECATED
#include "zipint.h"


ZIP_EXTERN int
zip_error_to_str(char *buf, zip_uint64_t len, int ze, int se) {
    const char *zs, *ss;

    if (ze < 0 || ze >= _zip_err_str_count) {
        return snprintf(buf, len, "Unknown error %d", ze);
    }

    zs = _zip_err_str[ze].description;

    switch (_zip_err_str[ze].type) {
        case ZIP_ET_SYS:
            ss = strerror(se);
            break;
            
        case ZIP_ET_ZLIB:
            ss = zError(se);
            break;
            
        default:
            ss = NULL;
    }

    return snprintf(buf, len, "%s%s%s", zs, (ss ? ": " : ""), (ss ? ss : ""));
}
