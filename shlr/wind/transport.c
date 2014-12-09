// Copyright (c) 2014, The Lemon Man, All rights reserved. LGPLv3

#include <stdio.h>
#include "transport.h"

extern io_backend_t iob_pipe;

static io_backend_t *io_backends[] = {
#if __WIN32__ || __CYGWIN__ || MINGW32
#warning TODO: add proper IO backend for windows here
#else
	&iob_pipe,
#endif
	NULL,
};

static io_backend_t *sel_backend = NULL;

int iob_select (const char *name) {
	io_backend_t *iob;

	iob = io_backends[0];

	if (!iob)
		return 0;

	if (sel_backend && sel_backend->deinit)
		sel_backend->deinit();

	sel_backend = iob;

	if (sel_backend->init)
		sel_backend->init();

	return 1;
}

void *iob_open (const char *path) {
	if (!sel_backend)
		return NULL;
	return sel_backend->open(path);
}

int iob_close (void *fp) {
	if (!sel_backend)
		return E_NOIF;
	return sel_backend->close(fp);
}

int iob_config (void *fp, void *cfg) {
	if (!sel_backend)
		return E_NOIF;
	return sel_backend->config(fp, cfg);
}

int iob_write (void *fp, const uint8_t *buf, const uint32_t buf_len) {
	uint32_t done;

	if (!sel_backend)
		return E_NOIF;

	for (done = 0; done < buf_len;) {
		int ret = sel_backend->write(fp, buf + done, buf_len - done, 100);
		if (ret<1) break;
		done += ret;
	}

	return done;
}

int iob_read (void *fp, uint8_t *buf, const uint32_t buf_len) {
	uint32_t done;

	if (!sel_backend)
		return E_NOIF;

	for (done = 0; done < buf_len;) {
		int ret = sel_backend->read(fp, buf + done, buf_len - done, 100);
		if (ret<1) break;
		done += ret;
	}

	return done;
}
