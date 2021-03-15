/* radare - LGPL3 - Copyright 2016-2020 - c0riolis, x0urc3 */

#ifndef PYC_MAGIC_H
#define PYC_MAGIC_H

#include <r_types.h>

struct pyc_version {
	ut32 magic;
	char *version;
	char *revision;
};

struct pyc_version get_pyc_version(ut32 magic);

double version2double(const char *version);

bool magic_int_within(ut32 target_magic, ut32 lower, ut32 uppper, bool *error);

#endif
