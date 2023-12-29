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

int py_version_cmp(char *va, char *vb, bool *err);
bool magic_int_within(char *ver, char *lower, char *uppper, bool *error);

#endif
