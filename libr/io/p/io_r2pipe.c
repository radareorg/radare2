/* radare - LGPL - Copyright 2015-2026 - pancake */

#include <r_io.h>
#include <r_socket.h>

typedef struct {
	R2Pipe *pipe;
	ut64 offset;
} R2PipeIO;

#define R2P(x) ((R2PipeIO*)(x)->data)

static RJson *__request(RIODesc *fd, const char *request) {
	if (r2pipe_write (R2P (fd)->pipe, request) < 1) {
		return NULL;
	}
	char *response = r2pipe_read (R2P (fd)->pipe);
	RJson *json = response? r_json_parsedup (response): NULL;
	free (response);
	if (json && json->type != R_JSON_OBJECT) {
		r_json_free (json);
		return NULL;
	}
	return json;
}

static int __result(const RJson *json, int count) {
	const RJson *result = json? r_json_get (json, "result"): NULL;
	if (!result || result->type != R_JSON_INTEGER || result->num.u_value > count) {
		return -1;
	}
	return result->num.u_value;
}

static int __write(RIO *io, RIODesc *fd, const ut8 *buf, int count) {
	if (!fd || !fd->data || count < 0) {
		return -1;
	}
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "op", "write");
	pj_kn (pj, "address", R2P (fd)->offset);
	pj_k (pj, "data");
	pj_a (pj);
	int i;
	for (i = 0; i < count; i++) {
		pj_n (pj, buf[i]);
	}
	pj_end (pj);
	pj_end (pj);
	RJson *json = __request (fd, pj_string (pj));
	pj_free (pj);
	int result = __result (json, count);
	if (result > 0) {
		R2P (fd)->offset += result;
	}
	r_json_free (json);
	return result;
}

static int __read(RIO *io, RIODesc *fd, ut8 *buf, int count) {
	if (!fd || !fd->data || count < 0) {
		return -1;
	}
	char *request = r_str_newf ("{\"op\":\"read\",\"address\":%"PFMT64u",\"count\":%d}",
		R2P (fd)->offset, count);
	RJson *json = __request (fd, request);
	free (request);
	int result = __result (json, count);
	if (!result) {
		goto beach;
	}
	const RJson *data = json? r_json_get (json, "data"): NULL;
	if (result < 0 || !data || data->type != R_JSON_ARRAY || data->children.count < result) {
		result = -1;
		goto beach;
	}
	const RJson *item = data->children.first;
	int i;
	for (i = 0; i < result; i++, item = item->next) {
		if (item->type != R_JSON_INTEGER || item->num.u_value > UT8_MAX) {
			result = -1;
			goto beach;
		}
		buf[i] = item->num.u_value;
	}
	R2P (fd)->offset += result;
beach:
	r_json_free (json);
	return result;
}

static bool __close(RIODesc *fd) {
	if (!fd || !fd->data) {
		return false;
	}
	r2pipe_close (R2P (fd)->pipe);
	R_FREE (fd->data);
	return true;
}

static ut64 __lseek(RIO *io, RIODesc *fd, ut64 offset, int whence) {
	switch (whence) {
	case R_IO_SEEK_SET:
		break;
	case R_IO_SEEK_CUR:
		offset += R2P (fd)->offset;
		break;
	case R_IO_SEEK_END:
		offset = UT64_MAX - 1;
		break;
	default:
		return UT64_MAX;
	}
	return R2P (fd)->offset = offset;
}

static bool __check(RIO *io, const char *pathname, bool many) {
	return r_str_startswith (pathname, "r2pipe://");
}

static RIODesc *__open(RIO *io, const char *pathname, int rw, int mode) {
	if (!__check (io, pathname, false)) {
		return NULL;
	}
	R2Pipe *pipe = r2pipe_open (pathname + 9);
	if (!pipe) {
		return NULL;
	}
	R2PipeIO *r2p = R_NEW0 (R2PipeIO);
	r2p->pipe = pipe;
	RIODesc *desc = r_io_desc_new (io, &r_io_plugin_r2pipe, pathname, rw, mode, r2p);
	if (!desc) {
		r2pipe_close (pipe);
		free (r2p);
	}
	return desc;
}

static char *__system(RIO *io, RIODesc *fd, const char *msg) {
	R_RETURN_VAL_IF_FAIL (io && fd && msg, NULL);
	PJ *pj = pj_new ();
	pj_o (pj);
	pj_ks (pj, "op", "system");
	pj_ks (pj, "cmd", msg);
	pj_end (pj);
	RJson *json = __request (fd, pj_string (pj));
	pj_free (pj);
	const RJson *result = json? r_json_get (json, "result"): NULL;
	char *response = NULL;
	if (result && result->type == R_JSON_STRING) {
		response = strdup (result->str_value);
	} else if (result && result->type == R_JSON_INTEGER) {
		response = r_str_newf ("%"PFMT64d, result->num.s_value);
	}
	r_json_free (json);
	return response;
}

RIOPlugin r_io_plugin_r2pipe = {
	.meta = {
		.name = "r2pipe",
		.author = "pancake",
		.desc = "r2pipe io plugin",
		.license = "MIT",
	},
	.uris = "r2pipe://",
	.open = __open,
	.close = __close,
	.read = __read,
	.check = __check,
	.seek = __lseek,
	.write = __write,
	.system = __system
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_IO,
	.data = &r_io_plugin_r2pipe,
	.version = R2_VERSION
};
#endif
