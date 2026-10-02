/* radare2 - MIT - Copyright 2026 - pancake */
// SPDX-License-Identifier: MIT

#ifndef R_OPENCORE_H
#define R_OPENCORE_H

// Stable lowlevel radare2 API resolved at runtime via dlopen/dlsym.
// Link libr_opencore.a or define R_OPENCORE_INLINE before including
// this header to get every function as static inline (header-only).

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef R_OPENCORE_INLINE
#define R_OPENCORE_API static inline
#ifndef R_OPENCORE_IMPL
#define R_OPENCORE_IMPL 1
#endif
#else
#define R_OPENCORE_API
#endif

#define R_OPENCORE_PERM_X 1
#define R_OPENCORE_PERM_W 2
#define R_OPENCORE_PERM_R 4
#define R_OPENCORE_PERM_RW (R_OPENCORE_PERM_R | R_OPENCORE_PERM_W)
#define R_OPENCORE_PERM_RWX (R_OPENCORE_PERM_RW | R_OPENCORE_PERM_X)
#define R_OPENCORE_ADDR_DEFAULT UINT64_MAX

// X (return type, radare2 symbol, arguments): every entry is resolved by r_opencore_init
#define R_OPENCORE_SYMBOLS(X) \
	X (void *, r_core_new, (void)) \
	X (void, r_core_free, (void *core)) \
	X (int, r_core_cmd0, (void *core, const char *cmd)) \
	X (char *, r_core_cmd_str, (void *core, const char *cmd)) \
	X (void *, r_core_file_open, (void *core, const char *file, int perm, uint64_t addr)) \
	X (bool, r_core_bin_load, (void *core, const char *file, uint64_t baddr)) \
	X (void *, r_core_get_config, (void *core)) \
	X (void *, r_core_get_io, (void *core)) \
	X (void *, r_core_get_lang, (void *core)) \
	X (void *, r_config_set, (void *cfg, const char *key, const char *value)) \
	X (void *, r_config_set_i, (void *cfg, const char *key, uint64_t value)) \
	X (void *, r_config_set_b, (void *cfg, const char *key, bool value)) \
	X (const char *, r_config_get, (void *cfg, const char *key)) \
	X (uint64_t, r_config_get_i, (void *cfg, const char *key)) \
	X (void *, r_buf_new_with_pointers, (const uint8_t *bytes, uint64_t len, bool steal)) \
	X (void, r_buf_fini, (void *buf)) \
	X (void *, r_io_open_buffer, (void *io, void *buf, int perm, int mode)) \
	X (bool, r_io_use_fd, (void *io, int fd)) \
	X (bool, r_lang_use, (void *lang, const char *name)) \
	X (bool, r_lang_run_string, (void *lang, const char *code)) \
	X (uint64_t, r_num_get, (void *num, const char *str)) \
	X (char *, r_hash_ssdeep, (const uint8_t *buf, size_t len)) \
	X (int, r_str_distance, (const char *a, const char *b)) \
	X (uint8_t *, r_inflate_lz4, (const uint8_t *src, int srclen, int *consumed, int *dstlen)) \
	X (void *, r_magic_new, (int flags)) \
	X (void, r_magic_free, (void *magic)) \
	X (bool, r_magic_load_buffer, (void *magic, const uint8_t *buf, size_t len)) \
	X (const char *, r_magic_buffer, (void *magic, const void *buf, size_t len)) \
	X (const char *, r_magic_error, (void *magic))

#define R_OPENCORE_FIELD(ret, name, args) ret (*name) args;
typedef struct r_opencore_api_t {
	R_OPENCORE_SYMBOLS (R_OPENCORE_FIELD)
} ROpenCoreApi;
#undef R_OPENCORE_FIELD

typedef struct r_opencore_lib_t {
	void *handle;
	ROpenCoreApi api;
	char error[256];
} ROpenCoreLib;

typedef struct r_opencore_t {
	void *core;
	void *config;
	void *io;
	void *lang;
	void *buf;
} ROpenCore;

typedef struct r_opencore_magic_t ROpenMagic;

// r_opencore_init must succeed before calling any other function
// libpath can be NULL to use $R2_OPENCORE_LIB or the default search paths
R_OPENCORE_API ROpenCoreLib *r_opencore_lib(void);
R_OPENCORE_API bool r_opencore_init(const char *libpath);
R_OPENCORE_API void r_opencore_fini(void);
R_OPENCORE_API const char *r_opencore_error(void);
R_OPENCORE_API void *r_opencore_sym(const char *name);

// core instance, returned strings must be released with free()
R_OPENCORE_API ROpenCore *r_opencore_new(void);
R_OPENCORE_API void r_opencore_free(ROpenCore *oc);
R_OPENCORE_API int r_opencore_cmd0(ROpenCore *oc, const char *cmd);
R_OPENCORE_API char *r_opencore_cmd(ROpenCore *oc, const char *cmd);
R_OPENCORE_API bool r_opencore_open(ROpenCore *oc, const char *file, int perm, uint64_t addr);
R_OPENCORE_API bool r_opencore_open_buffer(ROpenCore *oc, const uint8_t *data, uint64_t size, int perm);
R_OPENCORE_API bool r_opencore_bin_load(ROpenCore *oc, const char *file, uint64_t baddr);
R_OPENCORE_API bool r_opencore_config_set(ROpenCore *oc, const char *key, const char *value);
R_OPENCORE_API bool r_opencore_config_set_i(ROpenCore *oc, const char *key, uint64_t value);
R_OPENCORE_API bool r_opencore_config_set_b(ROpenCore *oc, const char *key, bool value);
R_OPENCORE_API const char *r_opencore_config_get(ROpenCore *oc, const char *key);
R_OPENCORE_API uint64_t r_opencore_config_get_i(ROpenCore *oc, const char *key);
R_OPENCORE_API bool r_opencore_lang_use(ROpenCore *oc, const char *name);
R_OPENCORE_API bool r_opencore_lang_run(ROpenCore *oc, const char *code);

// utilities that do not need a core instance
R_OPENCORE_API uint64_t r_opencore_num_get(const char *str);
R_OPENCORE_API char *r_opencore_hash_ssdeep(const uint8_t *buf, size_t len);
R_OPENCORE_API int r_opencore_str_distance(const char *a, const char *b);
R_OPENCORE_API uint8_t *r_opencore_inflate_lz4(const uint8_t *src, int srclen, int *consumed, int *dstlen);
R_OPENCORE_API ROpenMagic *r_opencore_magic_new(int flags);
R_OPENCORE_API void r_opencore_magic_free(ROpenMagic *magic);
R_OPENCORE_API bool r_opencore_magic_load_buffer(ROpenMagic *magic, const uint8_t *buf, size_t len);
R_OPENCORE_API const char *r_opencore_magic_buffer(ROpenMagic *magic, const void *buf, size_t len);
R_OPENCORE_API const char *r_opencore_magic_error(ROpenMagic *magic);

#ifdef R_OPENCORE_IMPL

#ifdef _WIN32
#include <windows.h>
#define R_OPENCORE_DLOPEN(x) ((void *)LoadLibraryA (x))
#define R_OPENCORE_DLSYM(h, x) ((void *)GetProcAddress ((HMODULE)(h), x))
#define R_OPENCORE_DLCLOSE(h) FreeLibrary ((HMODULE)(h))
#else
#include <dlfcn.h>
#define R_OPENCORE_DLOPEN(x) dlopen (x, RTLD_NOW | RTLD_LOCAL)
#define R_OPENCORE_DLSYM(h, x) dlsym (h, x)
#define R_OPENCORE_DLCLOSE(h) dlclose (h)
#endif

#if defined(_WIN32)
#define R_OPENCORE_LIBNAMES "r_core.dll", "libr_core.dll", "libr.dll"
#elif defined(__APPLE__)
#define R_OPENCORE_LIBNAMES "libr_core.dylib", "/usr/local/lib/libr_core.dylib", \
	"/opt/homebrew/lib/libr_core.dylib", "libr.dylib", "/usr/local/lib/libr.dylib"
#else
#define R_OPENCORE_LIBNAMES "libr_core.so", "/usr/local/lib/libr_core.so", \
	"/usr/lib/libr_core.so", "libr.so", "/usr/local/lib/libr.so"
#endif

R_OPENCORE_API ROpenCoreLib *r_opencore_lib(void) {
	static ROpenCoreLib lib;
	return &lib;
}

static inline bool r_opencore_load(ROpenCoreLib *lib, const char *libpath) {
	lib->handle = R_OPENCORE_DLOPEN (libpath);
	if (!lib->handle) {
		snprintf (lib->error, sizeof (lib->error), "cannot load %s", libpath);
		return false;
	}
#define R_OPENCORE_RESOLVE(ret, name, args) \
	lib->api.name = (ret (*) args)R_OPENCORE_DLSYM (lib->handle, #name); \
	if (!lib->api.name) { \
		snprintf (lib->error, sizeof (lib->error), "missing symbol %s in %s", #name, libpath); \
		r_opencore_fini (); \
		return false; \
	}
	R_OPENCORE_SYMBOLS (R_OPENCORE_RESOLVE)
#undef R_OPENCORE_RESOLVE
	lib->error[0] = 0;
	return true;
}

R_OPENCORE_API bool r_opencore_init(const char *libpath) {
	ROpenCoreLib *lib = r_opencore_lib ();
	if (lib->handle) {
		return true;
	}
	if (!libpath) {
		libpath = getenv ("R2_OPENCORE_LIB");
	}
	if (libpath && *libpath) {
		return r_opencore_load (lib, libpath);
	}
	const char *libnames[] = { R_OPENCORE_LIBNAMES };
	size_t i;
	for (i = 0; i < sizeof (libnames) / sizeof (libnames[0]); i++) {
		if (r_opencore_load (lib, libnames[i])) {
			return true;
		}
	}
	return false;
}

R_OPENCORE_API void r_opencore_fini(void) {
	ROpenCoreLib *lib = r_opencore_lib ();
	if (lib->handle) {
		R_OPENCORE_DLCLOSE (lib->handle);
	}
	lib->handle = NULL;
	memset (&lib->api, 0, sizeof (lib->api));
}

R_OPENCORE_API const char *r_opencore_error(void) {
	return r_opencore_lib ()->error;
}

R_OPENCORE_API void *r_opencore_sym(const char *name) {
	return R_OPENCORE_DLSYM (r_opencore_lib ()->handle, name);
}

#define R_OPENCORE_CALL(name) (r_opencore_lib ()->api.name)

R_OPENCORE_API ROpenCore *r_opencore_new(void) {
	void *core = R_OPENCORE_CALL (r_core_new) ();
	if (!core) {
		return NULL;
	}
	ROpenCore *oc = (ROpenCore *)calloc (1, sizeof (ROpenCore));
	if (!oc) {
		R_OPENCORE_CALL (r_core_free) (core);
		return NULL;
	}
	oc->core = core;
	oc->config = R_OPENCORE_CALL (r_core_get_config) (core);
	oc->io = R_OPENCORE_CALL (r_core_get_io) (core);
	oc->lang = R_OPENCORE_CALL (r_core_get_lang) (core);
	return oc;
}

static inline void r_opencore_buf_free(void *buf) {
	if (buf) {
		R_OPENCORE_CALL (r_buf_fini) (buf);
		free (buf);
	}
}

R_OPENCORE_API void r_opencore_free(ROpenCore *oc) {
	if (oc) {
		R_OPENCORE_CALL (r_core_free) (oc->core);
		r_opencore_buf_free (oc->buf);
		free (oc);
	}
}

R_OPENCORE_API int r_opencore_cmd0(ROpenCore *oc, const char *cmd) {
	return R_OPENCORE_CALL (r_core_cmd0) (oc->core, cmd);
}

R_OPENCORE_API char *r_opencore_cmd(ROpenCore *oc, const char *cmd) {
	return R_OPENCORE_CALL (r_core_cmd_str) (oc->core, cmd);
}

R_OPENCORE_API bool r_opencore_open(ROpenCore *oc, const char *file, int perm, uint64_t addr) {
	return R_OPENCORE_CALL (r_core_file_open) (oc->core, file, perm, addr) != NULL;
}

// data is borrowed, it must outlive the ROpenCore instance
R_OPENCORE_API bool r_opencore_open_buffer(ROpenCore *oc, const uint8_t *data, uint64_t size, int perm) {
	if (oc->buf) {
		return false;
	}
	void *buf = R_OPENCORE_CALL (r_buf_new_with_pointers) (data, size, false);
	if (!buf) {
		return false;
	}
	void *desc = R_OPENCORE_CALL (r_io_open_buffer) (oc->io, buf, perm, 0);
	if (!desc) {
		r_opencore_buf_free (buf);
		return false;
	}
	oc->buf = buf;
	// fd is the first field of RIODesc
	return R_OPENCORE_CALL (r_io_use_fd) (oc->io, *(const int *)desc);
}

R_OPENCORE_API bool r_opencore_bin_load(ROpenCore *oc, const char *file, uint64_t baddr) {
	return R_OPENCORE_CALL (r_core_bin_load) (oc->core, file, baddr);
}

R_OPENCORE_API bool r_opencore_config_set(ROpenCore *oc, const char *key, const char *value) {
	return R_OPENCORE_CALL (r_config_set) (oc->config, key, value) != NULL;
}

R_OPENCORE_API bool r_opencore_config_set_i(ROpenCore *oc, const char *key, uint64_t value) {
	return R_OPENCORE_CALL (r_config_set_i) (oc->config, key, value) != NULL;
}

R_OPENCORE_API bool r_opencore_config_set_b(ROpenCore *oc, const char *key, bool value) {
	return R_OPENCORE_CALL (r_config_set_b) (oc->config, key, value) != NULL;
}

R_OPENCORE_API const char *r_opencore_config_get(ROpenCore *oc, const char *key) {
	return R_OPENCORE_CALL (r_config_get) (oc->config, key);
}

R_OPENCORE_API uint64_t r_opencore_config_get_i(ROpenCore *oc, const char *key) {
	return R_OPENCORE_CALL (r_config_get_i) (oc->config, key);
}

R_OPENCORE_API bool r_opencore_lang_use(ROpenCore *oc, const char *name) {
	return R_OPENCORE_CALL (r_lang_use) (oc->lang, name);
}

R_OPENCORE_API bool r_opencore_lang_run(ROpenCore *oc, const char *code) {
	return R_OPENCORE_CALL (r_lang_run_string) (oc->lang, code);
}

R_OPENCORE_API uint64_t r_opencore_num_get(const char *str) {
	return R_OPENCORE_CALL (r_num_get) (NULL, str);
}

R_OPENCORE_API char *r_opencore_hash_ssdeep(const uint8_t *buf, size_t len) {
	return R_OPENCORE_CALL (r_hash_ssdeep) (buf, len);
}

R_OPENCORE_API int r_opencore_str_distance(const char *a, const char *b) {
	return R_OPENCORE_CALL (r_str_distance) (a, b);
}

R_OPENCORE_API uint8_t *r_opencore_inflate_lz4(const uint8_t *src, int srclen, int *consumed, int *dstlen) {
	return R_OPENCORE_CALL (r_inflate_lz4) (src, srclen, consumed, dstlen);
}

R_OPENCORE_API ROpenMagic *r_opencore_magic_new(int flags) {
	return (ROpenMagic *)R_OPENCORE_CALL (r_magic_new) (flags);
}

R_OPENCORE_API void r_opencore_magic_free(ROpenMagic *magic) {
	if (magic) {
		R_OPENCORE_CALL (r_magic_free) (magic);
	}
}

R_OPENCORE_API bool r_opencore_magic_load_buffer(ROpenMagic *magic, const uint8_t *buf, size_t len) {
	return R_OPENCORE_CALL (r_magic_load_buffer) (magic, buf, len);
}

R_OPENCORE_API const char *r_opencore_magic_buffer(ROpenMagic *magic, const void *buf, size_t len) {
	return R_OPENCORE_CALL (r_magic_buffer) (magic, buf, len);
}

R_OPENCORE_API const char *r_opencore_magic_error(ROpenMagic *magic) {
	return R_OPENCORE_CALL (r_magic_error) (magic);
}

#undef R_OPENCORE_CALL

#endif

#ifdef __cplusplus
}
#endif

#endif
