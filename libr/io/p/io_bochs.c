// Copyright (c) 2016 - LGPL, SkUaTeR, All rights reserved.

#include <r_io.h>
#include <r_lib.h>
#include <r_util.h>
#include <libbochs.h>

typedef struct {
	libbochs_t desc;    
} RIOBochs;

static libbochs_t *desc = NULL; 
static RIODesc *riobochs = NULL;
extern RIOPlugin r_io_plugin_bochs; // forward declaration

static bool __plugin_open(RIO *io, const char *file, bool many) {
	return !strncmp (file, "bochs://", strlen ("bochs://"));
}

static RIODesc *__open(RIO *io, const char *file, int rw, int mode) {
	RIOBochs  *riob;
	lprintf("io_open\n");
	const char *i;
	char * fileBochs = NULL;
	char * fileCfg = NULL;
	int l;
	if (!__plugin_open (io, file, 0)) {
		return NULL;
	}
	if (r_sandbox_enable (false)) {
		eprintf ("sandbox exit\n");
		return NULL;
	}
	if (riobochs) {
		return riobochs;
	}

       	i = strstr (file + 8, "#");
	if (i) {
		l = i - file - 8;
		fileBochs = r_str_ndup (file + 8, l);
		l = strlen (i + 1);
		fileCfg = strdup (i + 1);
	} else {
		free (fileCfg);
		eprintf ("Error cant find :\n");
		return NULL;
	}
	riob = R_NEW0 (RIOBochs);

	// Inicializamos
	if (bochs_open (&riob->desc, fileBochs, fileCfg) == true) {
		desc = &riob->desc;
		riobochs = r_io_desc_new (io, &r_io_plugin_bochs, file, rw, mode, riob);
		//riogdb = r_io_desc_new (&r_io_plugin_gdb, riog->desc.sock->fd, file, rw, mode, riog);
		free(fileBochs);
		free(fileCfg);
		return riobochs;
	}
	lprintf ("bochsio.open: Cannot connect to bochs.\n");
	free (riob);
	free (fileBochs);
	free (fileCfg);
	return NULL;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	lprintf("io_write\n");
	return -1;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	lprintf("io_seek %016"PFMT64x" \n",offset);
	return offset;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	memset (buf, 0xff, count);
	ut64 addr = io->off;
	if (!desc || !desc->data) 
		return -1;
        lprintf ("io_read ofs= %016"PFMT64x" count= %x\n", io->off, count);
	bochs_read (desc,addr,count,buf);
	return count;
}

static int __close(RIODesc *fd) {
	lprintf("io_close\n");
	bochs_close (desc);
	return true;
}
	
static int __system(RIO *io, RIODesc *fd, const char *cmd) {
        lprintf ("system command (%s)\n", cmd);
        if (!strcmp (cmd, "help")) {
                lprintf ("Usage: =!cmd args\n"
                        " =!:<bochscmd>      - Send a bochs command.\n"
                        " =!dobreak          - pause bochs.\n");
		lprintf ("io_system: Enviando comando bochs\n");
		bochs_send_cmd (desc, &cmd[1], true);
		io->cb_printf ("%s\n", desc->data);
		return 1;
	} else if (!strncmp (cmd, "dobreak", 7)) {
		bochs_cmd_stop (desc);
		io->cb_printf ("%s\n", desc->data);
		return 1;
	}         
        return true;
}

RIOPlugin r_io_plugin_bochs = {
	.name = "bochs",
	.desc = "Attach to a BOCHS debugger",
	.license = "LGPL3",
	.open = __open,
	.close = __close,
	.read = __read,
	.write = __write,
	.check = __plugin_open,
	.lseek = __lseek,
	.system = __system,
	.isdbg = true
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_bochs,
	.version = R2_VERSION
};
#endif
