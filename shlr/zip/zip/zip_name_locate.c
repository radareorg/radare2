/*
  zip_name_locate.c -- get index by name
  Copyright (C) 1999-2011 Dieter Baron and Thomas Klausner

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



#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>

#include "zipint.h"



ZIP_EXTERN zip_int64_t
zip_name_locate(struct zip *za, const char *fname, zip_flags_t flags)
{
    return _zip_name_locate(za, fname, flags, &za->error);
}



zip_int64_t
_zip_name_locate(struct zip *za, const char *fname, zip_flags_t flags, struct zip_error *error)
{
    int (*cmp)(const char *, const char *);
    const char *fn, *p;
    zip_uint64_t i;

    if (za == NULL)
	return -1;

    if (fname == NULL) {
	_zip_error_set(error, ZIP_ER_INVAL, 0);
	return -1;
    }

    cmp = (flags & ZIP_FL_NOCASE) ? __strcasecmp : strcmp;

    for (i=0; i<za->nentry; i++) {
	fn = _zip_get_name(za, i, flags, error);

	/* newly added (partially filled) entry or error */
	if (fn == NULL)
	    continue;
	
	if (flags & ZIP_FL_NODIR) {
	    p = strrchr(fn, '/');
	    if (p)
		fn = p+1;
	}

	if (cmp(fname, fn) == 0) {
	    _zip_error_clear(error);
	    return (zip_int64_t)i;
	}
    }

    _zip_error_set(error, ZIP_ER_NOENT, 0);
    return -1;
}
