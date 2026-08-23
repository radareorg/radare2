/* radare - MIT - Copyright 2026 - pancake */

#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>

#if defined(__HAIKU__) && DEBUGGER

#include <r_haiku.h>

#define RIOHDBG(x) ((RIOHaikuDbg *)((x)->data))

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return r_str_startswith (file, "hdbg://") || r_str_startswith (file, "attach://");
}

static int __read(RIO *io, RIODesc *desc, ut8 *buf, int len) {
	if (!desc || !desc->data) {
		return -1;
	}
	memset (buf, 0xff, len);
	// partial reads are fine, the missing bytes are left as 0xff
	return (r_haiku_mem (RIOHDBG (desc), io->off, buf, NULL, len) > 0)? len: -1;
}

static int __write(RIO *io, RIODesc *desc, const ut8 *buf, int len) {
	if (!desc || !desc->data) {
		return -1;
	}
	const int ret = r_haiku_mem (RIOHDBG (desc), io->off, NULL, buf, len);
	return (ret > 0)? ret: -1;
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	if (!__plugin_open (io, file, 0)) {
		return NULL;
	}
	const int pid = atoi (strstr (file, "://") + 3);
	if (pid < 1) {
		return NULL;
	}
	RIOHaikuDbg *hdbg = r_haiku_dbg_new (pid);
	if (!hdbg) {
		R_LOG_ERROR ("Cannot install the team debugger for %d", pid);
		return NULL;
	}
	RIODesc *desc = r_io_desc_new (io, &r_io_plugin_haiku, file, rw | R_PERM_X, mode, hdbg);
	if (desc) {
		desc->name = r_sys_pidpath (pid);
	} else {
		r_haiku_dbg_free (hdbg, true);
	}
	return desc;
}

static ut64 __lseek(RIO *io, RIODesc *desc, ut64 offset, int whence) {
	switch (whence) {
	case R_IO_SEEK_SET:
		io->off = offset;
		break;
	case R_IO_SEEK_CUR:
		io->off += offset;
		break;
	case R_IO_SEEK_END:
		io->off = UT64_MAX;
		break;
	}
	return io->off;
}

static bool __close(RIODesc *desc) {
	if (!desc || !desc->data) {
		return false;
	}
	r_haiku_dbg_free (RIOHDBG (desc), true);
	desc->data = NULL;
	return true;
}

static char *__system(RIO *io, RIODesc *desc, const char *cmd) {
	if (desc && desc->data && r_str_startswith (cmd, "pid")) {
		return r_str_newf ("%d", (int)RIOHDBG (desc)->team);
	}
	eprintf ("Usage: :pid  - show the debugged team id\n");
	return NULL;
}

static int __getpid(RIODesc *desc) {
	return (desc && desc->data)? (int)RIOHDBG (desc)->team: -1;
}

static int __gettid(RIODesc *desc) {
	if (!desc || !desc->data) {
		return -1;
	}
	RIOHaikuDbg *hdbg = RIOHDBG (desc);
	return (int)((hdbg->stopped_thread >= 0)? hdbg->stopped_thread: hdbg->main_thread);
}

static bool __getbase(RIODesc *desc, ut64 *base) {
	if (desc && desc->data && base) {
		image_info info;
		int32 cookie = 0;
		while (get_next_image_info (RIOHDBG (desc)->team, &cookie, &info) == B_OK) {
			if (info.type == B_APP_IMAGE) {
				*base = (ut64)(size_t)info.text;
				return true;
			}
		}
	}
	return false;
}

RIOPlugin r_io_plugin_haiku = {
	.meta = {
		.name = "haiku",
		.author = "pancake",
		.desc = "Debug a team using the Haiku kernel debugging api",
		.license = "MIT",
	},
	.uris = "hdbg://,attach://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __plugin_open,
	.seek = __lseek,
	.system = __system,
	.write = __write,
	.getpid = __getpid,
	.gettid = __gettid,
	.getbase = __getbase,
	.isdbg = true
};

#else

// non-haiku builds still need the symbol for the static plugin list; a NULL name keeps it unregistered
RIOPlugin r_io_plugin_haiku = {
	.meta = {
		.name = NULL
	},
};

#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_haiku,
	.version = R2_VERSION
};
#endif
