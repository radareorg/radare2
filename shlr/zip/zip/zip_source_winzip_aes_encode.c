/*
  zip_source_winzip_aes.c -- Winzip AES de/encryption routines
  Copyright (C) 2009-2016 Dieter Baron and Thomas Klausner

  This file is part of libzip, a library to manipulate ZIP archives.
  The authors can be contacted at <libzip@nih.at>

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
#include <string.h>

#include "zipint.h"

#include "gladman-fcrypt.h"

#define MAX_HEADER_LENGTH (16+PWD_VER_LENGTH)
#define HMAC_LENGTH 10

static unsigned int salt_length[] = { 0, 8, 12, 16 };

struct winzip_aes {
    char *password;
    unsigned int mode;
    zip_uint16_t encryption_method;

    zip_uint8_t data[MAX_HEADER_LENGTH];
    zip_buffer_t *buffer;

    fcrypt_ctx fcrypt_ctx;
    bool eof;
    zip_error_t error;
};


static int encrypt_header(zip_source_t *src, struct winzip_aes *ctx);
static void winzip_aes_free(struct winzip_aes *);
static zip_int64_t winzip_aes_encrypt(zip_source_t *src, void *ud, void *data, zip_uint64_t len, zip_source_cmd_t cmd);
static struct winzip_aes * winzip_aes_new(unsigned int mode, zip_uint16_t encryption_method, const char *password);


zip_source_t *
zip_source_winzip_aes_encode(zip_t *za, zip_source_t *src, zip_uint16_t encryption_method, int flags, const char *password)
{
    zip_source_t *s2;
    unsigned int mode = 0;
    struct winzip_aes *ctx;

    switch (encryption_method) {
    case ZIP_EM_AES_128:
	mode = 1;
	break;
    case ZIP_EM_AES_192:
	mode = 2;
	break;
    case ZIP_EM_AES_256:
	mode = 3;
	break;
    }
	
    if (password == NULL || src == NULL || mode == 0) {
	zip_error_set(&za->error, ZIP_ER_INVAL, 0);
	return NULL;
    }

    if (strlen(password) > UINT_MAX) {
        zip_error_set(&za->error, ZIP_ER_INVAL, 0); /* TODO: better error code? (password too long) */
        return NULL;
    }

    if ((ctx = winzip_aes_new(mode, encryption_method, password)) == NULL) {
	zip_error_set(&za->error, ZIP_ER_MEMORY, 0);
	return NULL;
    }

    if ((s2 = zip_source_layered(za, src, winzip_aes_encrypt, ctx)) == NULL) {
	winzip_aes_free(ctx);
	return NULL;
    }

    return s2;
}


static int
encrypt_header(zip_source_t *src, struct winzip_aes *ctx)
{
    if (!zip_random(ctx->data, (zip_uint16_t)salt_length[ctx->mode])) {
	zip_error_set(&ctx->error, ZIP_ER_INTERNAL, 0);
	return -1;
    }	
    
    if (_zip_fcrypt_init(ctx->mode, (unsigned char *)ctx->password, (unsigned int)strlen(ctx->password), ctx->data, ctx->data+salt_length[ctx->mode], &ctx->fcrypt_ctx) != 0) {
	zip_error_set(&ctx->error, ZIP_ER_MEMORY, 0);
	return -1;
    }

    if ((ctx->buffer = _zip_buffer_new(ctx->data, salt_length[ctx->mode] + PWD_VER_LENGTH)) == NULL) {
	zip_error_set(&ctx->error, ZIP_ER_MEMORY, 0);
	return -1;
    }
    
    return 0;
}


static zip_int64_t
winzip_aes_encrypt(zip_source_t *src, void *ud, void *data, zip_uint64_t length, zip_source_cmd_t cmd)
{
    struct winzip_aes *ctx;
    zip_int64_t ret;
    zip_uint64_t buffer_n, offset, n;

    ctx = (struct winzip_aes *)ud;

    switch (cmd) {
    case ZIP_SOURCE_OPEN:
	ctx->eof = false;
	if (encrypt_header(src, ctx) < 0) {
	    return -1;
	}
	return 0;

    case ZIP_SOURCE_READ:
	buffer_n = 0;
	
	if (ctx->buffer) {
	    buffer_n = _zip_buffer_read(ctx->buffer, data, length);

	    data = (zip_uint8_t *)data + buffer_n;
	    length -= buffer_n;
	    
	    if (_zip_buffer_eof(ctx->buffer)) {
		_zip_buffer_free(ctx->buffer);
		ctx->buffer = NULL;
	    }
	}

	if (ctx->eof) {
	    return (zip_int64_t)buffer_n;
	}

	if ((ret = zip_source_read(src, data, length)) < 0) {
	    _zip_error_set_from_source(&ctx->error, src);
	    return -1;
	}

	n = (zip_uint64_t)ret;
	for (offset = 0; offset < n; offset += ZIP_MIN(n - offset, UINT_MAX)) {
	    _zip_fcrypt_encrypt((zip_uint8_t *)data + offset, (unsigned int)ZIP_MIN(n - offset, UINT_MAX), &ctx->fcrypt_ctx);
	}

	if (n < length) {
	    ctx->eof = true;
	    _zip_fcrypt_end(ctx->data, &ctx->fcrypt_ctx);
	    if ((ctx->buffer = _zip_buffer_new(ctx->data, HMAC_LENGTH)) == NULL) {
		zip_error_set(&ctx->error, ZIP_ER_MEMORY, 0);
		/* TODO: return partial read? */
		return -1;
	    }
	}

	return (zip_int64_t)(buffer_n + n);

    case ZIP_SOURCE_CLOSE:
	return 0;

    case ZIP_SOURCE_STAT:
    {
	zip_stat_t *st;

	st = (zip_stat_t *)data;
	st->encryption_method = ctx->encryption_method;
	st->valid |= ZIP_STAT_ENCRYPTION_METHOD;
	if (st->valid & ZIP_STAT_COMP_SIZE) {
	    st->comp_size += 12 + salt_length[ctx->mode];
	}
	
	return 0;
    }
            
    case ZIP_SOURCE_SUPPORTS:
	return zip_source_make_command_bitmap(ZIP_SOURCE_OPEN, ZIP_SOURCE_READ, ZIP_SOURCE_CLOSE, ZIP_SOURCE_STAT, ZIP_SOURCE_ERROR, ZIP_SOURCE_FREE, -1);

    case ZIP_SOURCE_ERROR:
	return zip_error_to_data(&ctx->error, data, length);

    case ZIP_SOURCE_FREE:
	winzip_aes_free(ctx);
	return 0;

    default:
	zip_error_set(&ctx->error, ZIP_ER_INVAL, 0);
	return -1;
    }
}


static void
winzip_aes_free(struct winzip_aes *ctx)
{
    if (ctx == NULL) {
	return;
    }

    _zip_crypto_clear(&ctx->fcrypt_ctx, sizeof(ctx->fcrypt_ctx));
    _zip_crypto_clear(ctx->password, strlen(ctx->password));
    free(ctx->password);
    zip_error_fini(&ctx->error);
    _zip_buffer_free(ctx->buffer);
    free(ctx);
}


static struct winzip_aes *
winzip_aes_new(unsigned int mode, zip_uint16_t encryption_method, const char *password) {
    struct winzip_aes *ctx;
    
    if ((ctx = (struct winzip_aes *)malloc(sizeof(*ctx))) == NULL) {
	return NULL;
    }
    
    if ((ctx->password = strdup(password)) == NULL) {
	free(ctx);
	return NULL;
    }

    ctx->mode = mode;
    ctx->encryption_method = encryption_method;
    ctx->buffer = NULL;

    zip_error_init(&ctx->error);

    ctx->eof = false;
    return ctx;
}
