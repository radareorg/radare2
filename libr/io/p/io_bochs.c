// Copyright (c) 2016-2024 - LGPL, SkUaTeR, All rights reserved.

#include <r_io.h>
#include <r_lib.h>
#include <libbochs.h>

typedef struct {
	libbochs_t desc;
} RIOBochs;

static R_TH_LOCAL libbochs_t *desc = NULL;
static R_TH_LOCAL RIODesc *riobochs = NULL;
extern RIOPlugin r_io_plugin_bochs; // forward declaration

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return r_str_startswith (file, "bochs://");
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	char *fileBochs = NULL;
	char *fileCfg = NULL;
	int l;
	if (riobochs) {
		return riobochs;
	}
	if (!__plugin_open (io, file, 0)) {
		return NULL;
	}
	if (r_sandbox_enable (false)) {
		return NULL;
	}

	const char *i = strchr (file + 8, '#');
	if (i) {
		l = i - file - 8;
		fileBochs = r_str_ndup (file + 8, l);
		fileCfg = strdup (i + 1);
	} else {
		free (fileCfg);
		R_LOG_ERROR ("can't find :");
		return NULL;
	}
	RIOBochs  *riob = R_NEW0 (RIOBochs);
	if (bochs_open (&riob->desc, fileBochs, fileCfg) == true) {
		desc = &riob->desc;
		riobochs = r_io_desc_new (io, &r_io_plugin_bochs, file, rw, mode, riob);
		//riogdb = r_io_desc_new (&r_io_plugin_gdb, riog->desc.sock->fd, file, rw, mode, riog);
		free (fileBochs);
		free (fileCfg);
		return riobochs;
	}
	free (riob);
	free (fileBochs);
	free (fileCfg);
	return NULL;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	return -1;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	return offset;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, io->Oxff, count);
	ut64 addr = io->off;
	if (!desc || !desc->data) {
		return -1;
	}
	bochs_read (desc,addr,count,buf);
	return count;
}

static bool __close(RIODesc *fd) {
	bochs_close (desc);
	return true;
}

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
	if (*cmd == '?' || !strcmp (cmd, "help")) {
		eprintf ("Usage: :cmd args\n"
			" ::<bochscmd>      - Send a bochs command.\n"
			" :dobreak	  - pause bochs.\n");
		bochs_send_cmd (desc, &cmd[1], true);
		io->cb_printf ("%s\n", desc->data);
	} else if (r_str_startswith (cmd, "dobreak")) {
		bochs_cmd_stop (desc);
		io->cb_printf ("%s\n", desc->data);
	}
	return NULL;
}

RIOPlugin r_io_plugin_bochs = {
	.meta = {
		.name = "bochs",
		.author = "skuater",
		.desc = "Attach to a BOCHS debugger instance",
		.license = "LGPL-3.0-only",
	},
	.uris = "bochs://",
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.check = __plugin_open,
	.seek = __lseek,
	.system = __system,
	.isdbg = true
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_bochs,
	.version = R2_VERSION
};
#endif
