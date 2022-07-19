#ifndef _HAD_ZIP_SOURCE_FILE_STDIO_H
#define _HAD_ZIP_SOURCE_FILE_STDIO_H

/*
  zip_source_file_stdio.h -- common header for stdio file implementation
  Copyright (C) 2020 Dieter Baron and Thomas Klausner

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

void _zip_stdio_op_close(zip_source_file_context_t *ctx);
zip_int64_t _zip_stdio_op_read(zip_source_file_context_t *ctx, void *buf, zip_uint64_t len);
bool _zip_stdio_op_seek(zip_source_file_context_t *ctx, void *f, zip_int64_t offset, int whence);
bool _zip_stdio_op_stat(zip_source_file_context_t *ctx, zip_source_file_stat_t *st);
zip_int64_t _zip_stdio_op_tell(zip_source_file_context_t *ctx, void *f);

FILE *_zip_fopen_close_on_exec(const char *name, bool writeable);

#endif /* _HAD_ZIP_SOURCE_FILE_STDIO_H */
