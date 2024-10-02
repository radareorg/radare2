/*
  zip_source_file_stdio_named.c -- source for stdio file opened by name
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

#include "zipint.h"

#include "zip_source_file.h"
#include "zip_source_file_stdio.h"

#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#ifdef HAVE_CLONEFILE
#include <sys/attr.h>
#include <sys/clonefile.h>
#define CAN_CLONE
#endif
#ifdef HAVE_FICLONERANGE
#include <linux/fs.h>
#include <sys/ioctl.h>
#define CAN_CLONE
#endif

static zip_int64_t _zip_stdio_op_commit_write(zip_source_file_context_t *ctx);
#ifdef CAN_CLONE
static zip_int64_t _zip_stdio_op_create_temp_output_cloning(zip_source_file_context_t *ctx, zip_uint64_t offset);
#endif
static bool _zip_stdio_op_open(zip_source_file_context_t *ctx);
static zip_int64_t _zip_stdio_op_remove(zip_source_file_context_t *ctx);
static void _zip_stdio_op_rollback_write(zip_source_file_context_t *ctx);
static char *_zip_stdio_op_strdup(zip_source_file_context_t *ctx, const char *string);
static zip_int64_t _zip_stdio_op_write(zip_source_file_context_t *ctx, const void *data, zip_uint64_t len);

/* clang-format off */
static zip_source_file_operations_t ops_stdio_named = {
    _zip_stdio_op_close,
    _zip_stdio_op_commit_write,
    NULL, // _zip_stdio_op_create_temp_output,
#ifdef CAN_CLONE
    _zip_stdio_op_create_temp_output_cloning,
#else
    NULL,
#endif
    _zip_stdio_op_open,
    _zip_stdio_op_read,
    _zip_stdio_op_remove,
    _zip_stdio_op_rollback_write,
    _zip_stdio_op_seek,
    _zip_stdio_op_stat,
    _zip_stdio_op_strdup,
    _zip_stdio_op_tell,
    _zip_stdio_op_write
};
/* clang-format on */

ZIP_EXTERN zip_source_t *
zip_source_file(zip_t *za, const char *fname, zip_uint64_t start, zip_int64_t len) {
    if (za == NULL)
        return NULL;

    return zip_source_file_create(fname, start, len, &za->error);
}


ZIP_EXTERN zip_source_t *
zip_source_file_create(const char *fname, zip_uint64_t start, zip_int64_t length, zip_error_t *error) {
    if (fname == NULL || length < -1) {
        zip_error_set(error, ZIP_ER_INVAL, 0);
        return NULL;
    }

    return zip_source_file_common_new(fname, NULL, start, length, NULL, &ops_stdio_named, NULL, error);
}


static zip_int64_t
_zip_stdio_op_commit_write(zip_source_file_context_t *ctx) {
    if (fclose(ctx->fout) < 0) {
        zip_error_set(&ctx->error, ZIP_ER_WRITE, errno);
        return -1;
    }
    if (rename(ctx->tmpname, ctx->fname) < 0) {
        zip_error_set(&ctx->error, ZIP_ER_RENAME, errno);
        return -1;
    }

    return 0;
}


static bool
_zip_stdio_op_open(zip_source_file_context_t *ctx) {
    if ((ctx->f = _zip_fopen_close_on_exec(ctx->fname, false)) == NULL) {
        zip_error_set(&ctx->error, ZIP_ER_OPEN, errno);
        return false;
    }
    return true;
}


static zip_int64_t
_zip_stdio_op_remove(zip_source_file_context_t *ctx) {
    if (remove(ctx->fname) < 0) {
        zip_error_set(&ctx->error, ZIP_ER_REMOVE, errno);
        return -1;
    }
    return 0;
}


static void
_zip_stdio_op_rollback_write(zip_source_file_context_t *ctx) {
    if (ctx->fout) {
        fclose(ctx->fout);
    }
    (void)remove(ctx->tmpname);
}

static char *
_zip_stdio_op_strdup(zip_source_file_context_t *ctx, const char *string) {
    return strdup(string);
}


static zip_int64_t
_zip_stdio_op_write(zip_source_file_context_t *ctx, const void *data, zip_uint64_t len) {
    size_t ret;

    clearerr((FILE *)ctx->fout);
    ret = fwrite(data, 1, len, (FILE *)ctx->fout);
    if (ret != len || ferror((FILE *)ctx->fout)) {
        zip_error_set(&ctx->error, ZIP_ER_WRITE, errno);
        return -1;
    }

    return (zip_int64_t)ret;
}
