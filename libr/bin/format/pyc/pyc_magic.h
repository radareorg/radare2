/* radare - LGPL3 - Copyright 2016-2020 - c0riolis, x0urc3 */

#ifndef PYC_MAGIC_H
#define PYC_MAGIC_H

#include <r_types.h>

struct pyc_version {
	ut32 magic;
	const char *version;
	const char *revision;
};

struct pyc_version get_pyc_version(ut32 magic);

R_IPI int py_version_cmp(const char *va, const char *vb, bool *err);
R_IPI bool magic_int_within(const char *ver, const char *lower, const char *uppper, bool *error);

#endif
