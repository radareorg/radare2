// Copyright (c) 2014-2017, The Lemon Man, All rights reserved. LGPLv3
#include <r_util.h>
#include "transport.h"

io_desc_t *io_desc_new(io_backend_t *iob, void *fp) {
	io_desc_t *desc = R_NEW0 (io_desc_t);
	if (desc) {
		desc->iob = iob;
		desc->fp = fp;
	}
	return desc;
}

int iob_write(io_desc_t *desc, const uint8_t *buf, const uint32_t buf_len) {
	uint32_t done;
	static RThreadLock *lock = NULL;
	if (!lock) {
		lock = r_th_lock_new (true);
	}
	if (!desc || !desc->iob || !desc->fp) {
		return E_NOIF;
	}
	r_th_lock_enter (lock);
	for (done = 0; done < buf_len;) {
		int ret = desc->iob->write (desc->fp, buf + done, buf_len - done, 100);
		if (ret < 1) {
			break;
		}
		done += ret;
	}
	r_th_lock_leave (lock);
	return done;
}

int iob_read(io_desc_t *desc, uint8_t *buf, const uint32_t buf_len) {
	uint32_t done;
	static RThreadLock *lock = NULL;
	if (!lock) {
		lock = r_th_lock_new (true);
	}
	if (!desc || !desc->iob || !desc->fp) {
		return E_NOIF;
	}
	r_th_lock_enter (lock);
	for (done = 0; done < buf_len;) {
		int ret = desc->iob->read (desc->fp, buf + done, buf_len - done, 100);
		if (ret < 0) {
			break;
		}
		done += ret;
	}
	r_th_lock_leave (lock);
	return done;
}
