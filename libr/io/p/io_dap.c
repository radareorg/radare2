#include <r_userconf.h>
#include <r_io.h>
#include <r_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define IRAPI static inline
#include "libdapr.h"
#include "io_dap.h"

#define URI_PREFIX "dap://"

extern RIOPlugin r_io_plugin_dap; // forward declaration

static int __getpid(RIODesc *fd) {
    //RIODap *rio_foo = NULL;

    fd->io->cb_printf ("name = %s\n", fd->name);

    printf("%s\n", __func__);
    if (!fd || !fd->data) {
    	fd->io->cb_printf ("no more descriptor... Exit.\n");
        return -1;
    }

    //rio_foo = fd->data;
    return fd->io->desc ? fd->io->desc->fd : -1;
}


static bool __plugin_open(RIO *io, const char *file, bool many) {
	return r_str_startswith (file, "dap://");
}

static RIODesc *__open(RIO *io, const char *pathname, int flags, int mode) {
    printf("%s\n", __func__);
	RIODesc *dap_descriptor = R_NEW0 (RIODesc);
	RIODap *rio_dap = R_NEW0 (RIODap);
	char host[128], *port, *pid;
	int i_port;

	strncpy (host, pathname + 6, sizeof(host)-1);


	R_LOG_INFO ("host: %s\n", host);



    if (!__plugin_open(io, pathname, 0))
        return dap_descriptor;


    if (r_sandbox_enable (0)) {
		R_LOG_ERROR ("sandbox: Cannot use network");
		return NULL;
	}

	port = strchr (host , ':');
	if (!port) {
		R_LOG_ERROR ("Invalid debugger URI. Missing port number?");
		R_LOG_INFO ("Use gdb://host:port[/pid] for a network gdbserver");
		R_LOG_INFO ("Or gdb:///dev/DEVICENAME[@speed][:pid] for a serial gdbserver");
		return NULL;
	}
	*port = '\0';
	port++;
	pid = strchr (port, '/');


	printf("port = %s\n", port);



	int i_pid = -1;
	if (pid) {
		*pid = 0;
		pid++;
		i_pid = atoi (pid);
	}

	if (port) {
		i_port = atoi (port);
	}

	dapr_init (&rio_dap->desc, false);

	if (dapr_connect (&rio_dap->desc, host, i_port) == -1) {
		R_LOG_ERROR ("dap.io.open: Cannot connect to host");
	}

	if ((i_pid = rio_dap->desc.pid) < 0) {
		i_pid = -1;
	}

	//&rio_dap->desc.pid = i_pid;// FIXME this is here for now because RDebug's pid and libgdbr's aren't properly synced.
	if (dapr_attach (&rio_dap->desc, i_pid) < 0) {
		R_LOG_ERROR ("dapr: Failed to attach to PID %i", i_pid);
		return NULL;
	} else if ((i_pid = rio_dap->desc.pid) < 0) {
		i_pid = -1;
	}

    return r_io_desc_new (io, &r_io_plugin_dap, pathname, flags, mode, rio_dap);
}

static bool __close(RIODesc *fd) {
    printf("%s\n", __func__);
    if (!fd || !fd->data)
        return -1;

    R_FREE (fd->name);
    // destroy
    return true;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
    printf("%s, offset: %lx, io->off: %lx\n", __func__, offset, io->off);

    if (!fd || !fd->data)
        return -1;

    switch (whence) {
    case SEEK_SET:
        io->off = offset;
        break;
    case SEEK_CUR:
        io->off += (int)offset;
        break;
    case SEEK_END:
        io->off = UT64_MAX;
        break;
    }
    return io->off;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int len) {
    //RIODap *rio_foo = NULL;

    printf("%s, offset: %lx\n", __func__, io->off);

    if (!fd || !fd->data)
        return -1;

    //rio_foo = fd->data;

    return 0;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int len) {
    printf("%s\n", __func__);

    return 0;
}

/*static int __gettid(RIODesc *fd) {
    printf("%s\n", __func__);
    return 0;
}*/

static char *__system(RIO *io, RIODesc *fd, const char *cmd) {
    printf("%s command: %s\n", __func__, cmd);
    // io->cb_printf()

    if (cmd[0] == '?' || !strcmp (cmd, "help")) {
		eprintf ("Usage: :cmd args\n"
			 " :pid             - show targeted pid\n"
			 " :pkt s           - send packet 's'\n");
		return NULL;
    }

	if (r_str_startswith (cmd, "pid")) {
		long pid = (long) fd->plugin->getpid;
		if (!cmd[3]) {
			io->cb_printf ("%ld\n", pid);
		}
		return r_str_newf ("%ld", pid);
	}

    if (r_str_startswith (cmd, "system")) {
    	eprintf ("system command done!\n");
    }


    return NULL;
}

RIOPlugin r_io_plugin_dap = {
    .name = "dap",
    .desc = "IO DAP plugin",
    .license = "GPL3",
    .check = __plugin_open,
    .open = __open,
    .close = __close,
    .seek = __lseek,
    .read = __read,
    .write = __write,
    .getpid = __getpid,
    .system = __system,
    .isdbg = true,  // # --d flag
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_IO,
    .data = &r_io_plugin_dap,
    .version = R2_VERSION
};
#endif
