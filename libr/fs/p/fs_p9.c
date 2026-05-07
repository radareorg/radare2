/* radare - LGPL - Copyright 2026 - pancake */

#define R_LOG_ORIGIN "fs.p9"

#include <r_fs.h>
#include <r_lib.h>
#include <r_socket.h>

#include <limits.h>

#define P9_DEFAULT_HOST "127.0.0.1"
#define P9_DEFAULT_PORT "9999"
#define P9_DEFAULT_MSIZE 8192U
#define P9_MAX_MSG (1024U * 1024U)
#define P9_NOTAG ((ut16)0xffffU)
#define P9_NOFID ((ut32)0xffffffffU)
#define P9_QID_SIZE 13
#define P9_STAT_HEADER_SIZE 6
#define P9_DMDIR 0x80000000U
#define P9_OREAD 0
#define P9_OWRITE 1
#define P9_OTRUNC 0x10

typedef enum {
	P9_TRANSPORT_TCP,
	P9_TRANSPORT_UDP,
	P9_TRANSPORT_UNIX,
} P9Transport;

enum {
	P9_TVERSION = 100,
	P9_RVERSION = 101,
	P9_TATTACH = 104,
	P9_RATTACH = 105,
	P9_RERROR = 107,
	P9_TWALK = 110,
	P9_RWALK = 111,
	P9_TOPEN = 112,
	P9_ROPEN = 113,
	P9_TCREATE = 114,
	P9_RCREATE = 115,
	P9_TREAD = 116,
	P9_RREAD = 117,
	P9_TWRITE = 118,
	P9_RWRITE = 119,
	P9_TCLUNK = 120,
	P9_RCLUNK = 121,
	P9_TREMOVE = 122,
	P9_RREMOVE = 123,
	P9_TSTAT = 124,
	P9_RSTAT = 125
};

typedef struct p9_buf_t {
	ut8 *p;
	size_t n;
	size_t cap;
	bool fail;
} P9Buf;

typedef struct p9_in_t {
	const ut8 *p;
	size_t n;
	size_t off;
	bool fail;
} P9In;

typedef struct p9_stat_t {
	ut8 qtype;
	ut32 qvers;
	ut64 qpath;
	ut32 mode;
	ut32 atime;
	ut32 mtime;
	ut64 length;
	char *name;
	char *uid;
	char *gid;
	char *muid;
} P9Stat;

typedef struct p9_client_t {
	RSocket *sock;
	ut32 msize;
	ut16 tag;
	ut32 nextfid;
	ut32 rootfid;
	P9Transport transport;
	char *host;
	char *port;
	char *path;
	char *uname;
	char *aname;
} P9Client;

typedef struct p9_file_t {
	P9Client *client;
	ut32 fid;
} P9File;

static char *p9_cfg_host = NULL;
static char *p9_cfg_port = NULL;
static char *p9_cfg_transport = NULL;
static char *p9_cfg_path = NULL;
static char *p9_cfg_uname = NULL;
static char *p9_cfg_aname = NULL;

static bool p9_buf_reserve(P9Buf *b, size_t add) {
	R_RETURN_VAL_IF_FAIL (b, false);
	if (b->fail) {
		return false;
	}
	if (add > SIZE_MAX - b->n) {
		b->fail = true;
		return false;
	}
	size_t want = b->n + add;
	if (want <= b->cap) {
		return true;
	}
	size_t cap = b->cap? b->cap: 128;
	while (cap < want) {
		if (cap > SIZE_MAX / 2) {
			b->fail = true;
			return false;
		}
		cap *= 2;
	}
	ut8 *p = realloc (b->p, cap);
	if (!p) {
		b->fail = true;
		return false;
	}
	b->p = p;
	b->cap = cap;
	return true;
}

static void p9_put1(P9Buf *b, ut8 v) {
	if (p9_buf_reserve (b, 1)) {
		b->p[b->n++] = v;
	}
}

static void p9_put2(P9Buf *b, ut16 v) {
	if (p9_buf_reserve (b, 2)) {
		r_write_le16 (b->p + b->n, v);
		b->n += 2;
	}
}

static void p9_put4(P9Buf *b, ut32 v) {
	if (p9_buf_reserve (b, 4)) {
		r_write_le32 (b->p + b->n, v);
		b->n += 4;
	}
}

static void p9_put8(P9Buf *b, ut64 v) {
	if (p9_buf_reserve (b, 8)) {
		r_write_le64 (b->p + b->n, v);
		b->n += 8;
	}
}

static void p9_put_bytes(P9Buf *b, const ut8 *p, size_t n) {
	if (n && p9_buf_reserve (b, n)) {
		memcpy (b->p + b->n, p, n);
		b->n += n;
	}
}

static void p9_put_str(P9Buf *b, const char *s) {
	size_t n = s? strlen (s): 0;
	if (n > UT16_MAX) {
		b->fail = true;
		return;
	}
	p9_put2 (b, (ut16)n);
	p9_put_bytes (b, (const ut8 *)s, n);
}

static void p9_msg_begin(P9Buf *b, ut8 type, ut16 tag) {
	memset (b, 0, sizeof (*b));
	p9_put4 (b, 0);
	p9_put1 (b, type);
	p9_put2 (b, tag);
}

static void p9_buf_free(P9Buf *b) {
	if (b) {
		free (b->p);
		memset (b, 0, sizeof (*b));
	}
}

static bool p9_get1(P9In *in, ut8 *v) {
	if (!in || !v || in->off + 1 > in->n) {
		if (in) {
			in->fail = true;
		}
		return false;
	}
	*v = in->p[in->off++];
	return true;
}

static bool p9_get2(P9In *in, ut16 *v) {
	if (!in || !v || in->off + 2 > in->n) {
		if (in) {
			in->fail = true;
		}
		return false;
	}
	*v = r_read_le16 (in->p + in->off);
	in->off += 2;
	return true;
}

static bool p9_get4(P9In *in, ut32 *v) {
	if (!in || !v || in->off + 4 > in->n) {
		if (in) {
			in->fail = true;
		}
		return false;
	}
	*v = r_read_le32 (in->p + in->off);
	in->off += 4;
	return true;
}

static bool p9_get8(P9In *in, ut64 *v) {
	if (!in || !v || in->off + 8 > in->n) {
		if (in) {
			in->fail = true;
		}
		return false;
	}
	*v = r_read_le64 (in->p + in->off);
	in->off += 8;
	return true;
}

static char *p9_get_str(P9In *in) {
	ut16 n = 0;
	if (!p9_get2 (in, &n) || in->off + n > in->n) {
		in->fail = true;
		return NULL;
	}
	char *s = n? r_str_newlen ((const char *)in->p + in->off, n): r_str_new ("");
	if (!s) {
		in->fail = true;
		return NULL;
	}
	in->off += n;
	return s;
}

static bool p9_skip(P9In *in, size_t n) {
	if (!in || in->off > in->n || n > in->n - in->off) {
		if (in) {
			in->fail = true;
		}
		return false;
	}
	in->off += n;
	return true;
}

static int p9_sock_readn(RSocket *s, ut8 *buf, size_t len) {
	size_t off = 0;
	while (off < len) {
		size_t want = len - off;
		int got = r_socket_read (s, buf + off, want > INT_MAX? INT_MAX: (int)want);
		if (got <= 0) {
			return -1;
		}
		off += (size_t)got;
	}
	return 0;
}

static int p9_sock_writen(RSocket *s, const ut8 *buf, size_t len) {
	size_t off = 0;
	while (off < len) {
		size_t want = len - off;
		int wrote = r_socket_write (s, buf + off, want > INT_MAX? INT_MAX: (int)want);
		if (wrote <= 0) {
			return -1;
		}
		off += (size_t)wrote;
	}
	return 0;
}

static bool p9_read_msg(P9Client *c, ut8 **out, size_t *outlen) {
	RSocket *s = c->sock;
	if (c->transport == P9_TRANSPORT_UDP) {
		ut8 *p = malloc (P9_MAX_MSG);
		if (!p) {
			return false;
		}
		int got = r_socket_read (s, p, P9_MAX_MSG);
		if (got < 7) {
			free (p);
			return false;
		}
		ut32 sz = r_read_le32 (p);
		if (sz < 7 || sz > (ut32)got) {
			free (p);
			return false;
		}
		*out = p;
		*outlen = sz;
		return true;
	}
	ut8 hdr[4];
	if (p9_sock_readn (s, hdr, sizeof (hdr)) < 0) {
		return false;
	}
	ut32 sz = r_read_le32 (hdr);
	if (sz < 7 || sz > P9_MAX_MSG) {
		return false;
	}
	ut8 *p = malloc (sz);
	if (!p) {
		return false;
	}
	memcpy (p, hdr, 4);
	if (p9_sock_readn (s, p + 4, sz - 4) < 0) {
		free (p);
		return false;
	}
	*out = p;
	*outlen = sz;
	return true;
}

static bool p9_send_buf(RSocket *s, P9Buf *b) {
	if (!b || b->fail || b->n < 7 || b->n > P9_MAX_MSG) {
		return false;
	}
	r_write_le32 (b->p, (ut32)b->n);
	return p9_sock_writen (s, b->p, b->n) == 0;
}

static char *p9_parse_rerror(const ut8 *pkt, size_t len) {
	P9In in = { pkt, len, 7, false };
	char *s = p9_get_str (&in);
	return s? s: strdup ("remote error");
}

static ut16 p9_next_tag(P9Client *c) {
	c->tag++;
	if (c->tag == P9_NOTAG) {
		c->tag++;
	}
	return c->tag;
}

static ut32 p9_next_fid(P9Client *c) {
	c->nextfid++;
	if (c->nextfid == P9_NOFID || c->nextfid == c->rootfid) {
		c->nextfid = c->rootfid + 1;
	}
	return c->nextfid;
}

static bool p9_rpc(P9Client *c, P9Buf *req, ut8 expect, ut8 **out, size_t *outlen, char **err) {
	if (!p9_send_buf (c->sock, req)) {
		*err = strdup ("send failed");
		return false;
	}
	ut8 *pkt = NULL;
	size_t len = 0;
	if (!p9_read_msg (c, &pkt, &len)) {
		*err = strdup ("receive failed");
		return false;
	}
	if (len < 7) {
		free (pkt);
		*err = strdup ("short reply");
		return false;
	}
	ut8 type = pkt[4];
	if (type == P9_RERROR) {
		*err = p9_parse_rerror (pkt, len);
		free (pkt);
		return false;
	}
	if (type != expect) {
		*err = r_str_newf ("unexpected reply type %u", (unsigned)type);
		free (pkt);
		return false;
	}
	if (r_read_le16 (pkt + 5) != r_read_le16 (req->p + 5)) {
		*err = strdup ("reply tag mismatch");
		free (pkt);
		return false;
	}
	*out = pkt;
	*outlen = len;
	return true;
}

static bool p9_rpc_drop(P9Client *c, P9Buf *req, ut8 expect, char **err) {
	ut8 *pkt = NULL;
	size_t len = 0;
	bool ok = p9_rpc (c, req, expect, &pkt, &len, err);
	p9_buf_free (req);
	free (pkt);
	return ok;
}

static bool p9_client_version(P9Client *c, char **err) {
	P9Buf b;
	p9_msg_begin (&b, P9_TVERSION, P9_NOTAG);
	p9_put4 (&b, P9_DEFAULT_MSIZE);
	p9_put_str (&b, "9P2000");
	ut8 *pkt = NULL;
	size_t len = 0;
	bool ok = p9_rpc (c, &b, P9_RVERSION, &pkt, &len, err);
	p9_buf_free (&b);
	if (!ok) {
		return false;
	}
	P9In in = { pkt, len, 7, false };
	ut32 msize = 0;
	p9_get4 (&in, &msize);
	char *version = p9_get_str (&in);
	if (in.fail || !version || strncmp (version, "9P2000", 6)) {
		free (version);
		free (pkt);
		*err = strdup ("bad Rversion");
		return false;
	}
	c->msize = msize;
	free (version);
	free (pkt);
	return true;
}

static bool p9_client_attach(P9Client *c, char **err) {
	P9Buf b;
	p9_msg_begin (&b, P9_TATTACH, p9_next_tag (c));
	p9_put4 (&b, c->rootfid);
	p9_put4 (&b, P9_NOFID);
	p9_put_str (&b, c->uname);
	p9_put_str (&b, c->aname);
	return p9_rpc_drop (c, &b, P9_RATTACH, err);
}

static RList *p9_split_path(const char *path) {
	if (!path || !strcmp (path, "/") || !*path) {
		return NULL;
	}
	RList *names = r_str_split_duplist (path, "/", false);
	if (!names) {
		return NULL;
	}
	RListIter *it;
	RListIter *tmp;
	char *name;
	r_list_foreach_safe (names, it, tmp, name) {
		if (!name) {
			r_list_free (names);
			return NULL;
		}
		if (!*name || !strcmp (name, ".")) {
			r_list_delete (names, it);
		}
	}
	return names;
}

static bool p9_walk(P9Client *c, ut32 fromfid, ut32 newfid, const char *path, char **err) {
	RList *names = p9_split_path (path);
	int nname = names? r_list_length (names): 0;
	if (nname > UT16_MAX) {
		r_list_free (names);
		*err = strdup ("path too deep");
		return false;
	}
	P9Buf b;
	p9_msg_begin (&b, P9_TWALK, p9_next_tag (c));
	p9_put4 (&b, fromfid);
	p9_put4 (&b, newfid);
	p9_put2 (&b, (ut16)nname);
	RListIter *it;
	char *name;
	r_list_foreach (names, it, name) {
		p9_put_str (&b, name);
	}
	r_list_free (names);
	ut8 *pkt = NULL;
	size_t len = 0;
	bool ok = p9_rpc (c, &b, P9_RWALK, &pkt, &len, err);
	p9_buf_free (&b);
	if (!ok) {
		return false;
	}
	P9In in = { pkt, len, 7, false };
	ut16 nwqid = 0;
	ut16 i;
	p9_get2 (&in, &nwqid);
	for (i = 0; i < nwqid; i++) {
		p9_skip (&in, P9_QID_SIZE);
	}
	free (pkt);
	if (in.fail || nwqid != nname) {
		*err = strdup ("walk failed");
		return false;
	}
	return true;
}

static bool p9_open(P9Client *c, ut32 fid, ut8 mode, char **err) {
	P9Buf b;
	p9_msg_begin (&b, P9_TOPEN, p9_next_tag (c));
	p9_put4 (&b, fid);
	p9_put1 (&b, mode);
	return p9_rpc_drop (c, &b, P9_ROPEN, err);
}

static bool p9_create(P9Client *c, ut32 fid, const char *name, ut32 perm, ut8 mode, char **err) {
	P9Buf b;
	p9_msg_begin (&b, P9_TCREATE, p9_next_tag (c));
	p9_put4 (&b, fid);
	p9_put_str (&b, name);
	p9_put4 (&b, perm);
	p9_put1 (&b, mode);
	return p9_rpc_drop (c, &b, P9_RCREATE, err);
}

static bool p9_clunk(P9Client *c, ut32 fid, char **err) {
	P9Buf b;
	p9_msg_begin (&b, P9_TCLUNK, p9_next_tag (c));
	p9_put4 (&b, fid);
	return p9_rpc_drop (c, &b, P9_RCLUNK, err);
}

static bool p9_remove(P9Client *c, ut32 fid, char **err) {
	P9Buf b;
	p9_msg_begin (&b, P9_TREMOVE, p9_next_tag (c));
	p9_put4 (&b, fid);
	return p9_rpc_drop (c, &b, P9_RREMOVE, err);
}

static bool p9_read_once(P9Client *c, ut32 fid, ut64 off, ut32 count, ut8 **data, ut32 *dlen, char **err) {
	P9Buf b;
	p9_msg_begin (&b, P9_TREAD, p9_next_tag (c));
	p9_put4 (&b, fid);
	p9_put8 (&b, off);
	p9_put4 (&b, count);
	ut8 *pkt = NULL;
	size_t len = 0;
	bool ok = p9_rpc (c, &b, P9_RREAD, &pkt, &len, err);
	p9_buf_free (&b);
	if (!ok) {
		return false;
	}
	P9In in = { pkt, len, 7, false };
	p9_get4 (&in, dlen);
	if (in.fail || in.off + *dlen > in.n || *dlen > count) {
		free (pkt);
		*err = strdup ("bad Rread");
		return false;
	}
	*data = *dlen? r_mem_dup (pkt + in.off, *dlen): malloc (1);
	if (!*data) {
		free (pkt);
		*err = strdup ("out of memory");
		return false;
	}
	free (pkt);
	return true;
}

static bool p9_write_once(P9Client *c, ut32 fid, ut64 off, const ut8 *data, ut32 len, ut32 *wrote, char **err) {
	P9Buf b;
	p9_msg_begin (&b, P9_TWRITE, p9_next_tag (c));
	p9_put4 (&b, fid);
	p9_put8 (&b, off);
	p9_put4 (&b, len);
	p9_put_bytes (&b, data, len);
	ut8 *pkt = NULL;
	size_t plen = 0;
	bool ok = p9_rpc (c, &b, P9_RWRITE, &pkt, &plen, err);
	p9_buf_free (&b);
	if (!ok) {
		return false;
	}
	P9In in = { pkt, plen, 7, false };
	p9_get4 (&in, wrote);
	free (pkt);
	if (in.fail || *wrote > len) {
		*err = strdup ("bad Rwrite");
		return false;
	}
	return true;
}

static bool p9_get_stat(P9In *in, P9Stat *st) {
	if (!p9_skip (in, P9_STAT_HEADER_SIZE)) {
		return false;
	}
	p9_get1 (in, &st->qtype);
	p9_get4 (in, &st->qvers);
	p9_get8 (in, &st->qpath);
	p9_get4 (in, &st->mode);
	p9_get4 (in, &st->atime);
	p9_get4 (in, &st->mtime);
	p9_get8 (in, &st->length);
	st->name = p9_get_str (in);
	st->uid = p9_get_str (in);
	st->gid = p9_get_str (in);
	st->muid = p9_get_str (in);
	return !in->fail && st->name && st->uid && st->gid && st->muid;
}

static bool p9_stat(P9Client *c, ut32 fid, P9Stat *st, char **err) {
	P9Buf b;
	p9_msg_begin (&b, P9_TSTAT, p9_next_tag (c));
	p9_put4 (&b, fid);
	ut8 *pkt = NULL;
	size_t len = 0;
	bool ok = p9_rpc (c, &b, P9_RSTAT, &pkt, &len, err);
	p9_buf_free (&b);
	if (!ok) {
		return false;
	}
	P9In in = { pkt, len, 7, false };
	ut16 size = 0;
	bool parsed = false;
	p9_get2 (&in, &size);
	if (!in.fail && in.off + size <= in.n) {
		in.n = in.off + size;
		parsed = p9_get_stat (&in, st);
	}
	free (pkt);
	if (!parsed) {
		*err = strdup ("bad Rstat");
		return false;
	}
	return true;
}

static void p9_stat_free(P9Stat *st) {
	if (st) {
		free (st->name);
		free (st->uid);
		free (st->gid);
		free (st->muid);
		memset (st, 0, sizeof (*st));
	}
}

static bool p9_parse_stat_record(const ut8 *buf, size_t len, size_t *off, P9Stat *st) {
	if (*off + 2 > len) {
		return false;
	}
	ut16 size = r_read_le16 (buf + *off);
	if (*off + 2 + size > len) {
		return false;
	}
	P9In in = { buf, *off + 2 + size, *off + 2, false };
	*off += 2 + size;
	return p9_get_stat (&in, st);
}

static char p9_file_type(const P9Stat *st) {
	return (st->mode & P9_DMDIR)? R_FS_FILE_TYPE_DIRECTORY: R_FS_FILE_TYPE_REGULAR;
}

static void p9_file_fill(RFSFile *file, const P9Stat *st) {
	file->type = p9_file_type (st);
	file->time = st->mtime;
	file->perm = st->mode & 0777;
	file->size = st->length > UT32_MAX? UT32_MAX: (ut32)st->length;
}

static void p9_append_file(RList *list, const P9Stat *st) {
	RFSFile *fsf = r_fs_file_new (NULL, st->name? st->name: "");
	if (fsf) {
		p9_file_fill (fsf, st);
		r_list_append (list, fsf);
	}
}

static ut32 p9_max_read(P9Client *c) {
	return c->msize > 11? c->msize - 11: 0;
}

static ut32 p9_max_write(P9Client *c) {
	return c->msize > 23? c->msize - 23: 0;
}

static void p9_set_string(char **dst, const char *src);

static const char *p9_transport_name(P9Transport transport) {
	switch (transport) {
	case P9_TRANSPORT_UDP:
		return "udp";
	case P9_TRANSPORT_UNIX:
		return "unix";
	case P9_TRANSPORT_TCP:
	default:
		return "tcp";
	}
}

static P9Transport p9_transport_from_string(const char *s) {
	if (s && !r_str_casecmp (s, "udp")) {
		return P9_TRANSPORT_UDP;
	}
	if (s && (!r_str_casecmp (s, "unix") || !r_str_casecmp (s, "unixsocket"))) {
		return P9_TRANSPORT_UNIX;
	}
	return P9_TRANSPORT_TCP;
}

static char *p9_cfg_dup(const char *env, const char *configured, const char *fallback) {
	char *s = r_sys_getenv (env);
	if (R_STR_ISNOTEMPTY (s)) {
		return s;
	}
	free (s);
	return strdup (R_STR_ISNOTEMPTY (configured)? configured: fallback);
}

static char *p9_cfg_user(void) {
	char *s = p9_cfg_dup ("R2_FS_9FS_USER", p9_cfg_uname, "");
	if (R_STR_ISNOTEMPTY (s)) {
		return s;
	}
	free (s);
	s = r_sys_getenv ("USER");
	if (R_STR_ISNOTEMPTY (s)) {
		return s;
	}
	free (s);
	return strdup ("none");
}

static bool p9_client_apply_addr(P9Client *c, const char *addr) {
	if (R_STR_ISEMPTY (addr)) {
		return false;
	}
	if (*addr == '/') {
		c->transport = P9_TRANSPORT_UNIX;
		p9_set_string (&c->path, addr);
		return true;
	}
	const char *host = addr;
	const char *port = NULL;
	char *tmp = NULL;
	if (r_str_startswith (addr, "tcp!") || r_str_startswith (addr, "udp!")) {
		c->transport = *addr == 'u'? P9_TRANSPORT_UDP: P9_TRANSPORT_TCP;
		host = addr + 4;
		port = strrchr (host, '!');
		if (!port || port == host) {
			return false;
		}
		tmp = r_str_ndup (host, port - host);
		host = tmp;
		port++;
	} else if (r_str_startswith (addr, "unix!")) {
		c->transport = P9_TRANSPORT_UNIX;
		p9_set_string (&c->path, addr + 5);
		return true;
	} else if (r_str_startswith (addr, "unix:")) {
		c->transport = P9_TRANSPORT_UNIX;
		p9_set_string (&c->path, addr + 5);
		return true;
	} else {
		port = strrchr (addr, ':');
		if (port && port != addr) {
			tmp = r_str_ndup (addr, port - addr);
			host = tmp;
			port++;
		}
	}
	if (R_STR_ISNOTEMPTY (host)) {
		p9_set_string (&c->host, host);
	}
	if (R_STR_ISNOTEMPTY (port)) {
		p9_set_string (&c->port, port);
	}
	free (tmp);
	return true;
}

static void p9_client_apply_option(P9Client *c, const char *key, const char *value) {
	if (!r_str_casecmp (key, "transport") || !r_str_casecmp (key, "proto")) {
		c->transport = p9_transport_from_string (value);
	} else if (!r_str_casecmp (key, "host") || !r_str_casecmp (key, "server")) {
		p9_set_string (&c->host, value);
	} else if (!r_str_casecmp (key, "port") || !r_str_casecmp (key, "service")) {
		p9_set_string (&c->port, value);
	} else if (!r_str_casecmp (key, "socket")) {
		c->transport = P9_TRANSPORT_UNIX;
		p9_set_string (&c->path, value);
	} else if (!r_str_casecmp (key, "path")) {
		p9_set_string (&c->path, value);
	} else if (!r_str_casecmp (key, "user") || !r_str_casecmp (key, "uname")) {
		p9_set_string (&c->uname, value);
	} else if (!r_str_casecmp (key, "aname") || !r_str_casecmp (key, "attach")) {
		p9_set_string (&c->aname, value);
	} else if (!r_str_casecmp (key, "addr") || !r_str_casecmp (key, "remote")) {
		p9_client_apply_addr (c, value);
	}
}

typedef void (*P9ApplyAddrCb)(void *user, const char *addr);
typedef void (*P9ApplyOptionCb)(void *user, const char *key, const char *value);

static void p9_apply_options(const char *options, void *user, P9ApplyAddrCb apply_addr, P9ApplyOptionCb apply_option) {
	if (R_STR_ISEMPTY (options)) {
		return;
	}
	char *opts = strdup (options);
	if (!opts) {
		return;
	}
	r_str_replace_char (opts, ';', ',');
	int count = r_str_split (opts, ',');
	int i;
	for (i = 0; i < count; i++) {
		char *tok = (char *)r_str_trim_head_ro (r_str_word_get0 (opts, i));
		r_str_trim_tail (tok);
		if (!*tok) {
			continue;
		}
		char *eq = strchr (tok, '=');
		if (!eq) {
			apply_addr (user, tok);
			continue;
		}
		*eq++ = 0;
		r_str_trim_tail (tok);
		eq = (char *)r_str_trim_head_ro (eq);
		r_str_trim_tail (eq);
		if (*tok) {
			apply_option (user, tok, eq);
		}
	}
	free (opts);
}

static void p9_client_apply_addr_cb(void *user, const char *addr) {
	p9_client_apply_addr ((P9Client *)user, addr);
}

static void p9_client_apply_option_cb(void *user, const char *key, const char *value) {
	p9_client_apply_option ((P9Client *)user, key, value);
}

static void p9_client_apply_options(P9Client *c, const char *options) {
	p9_apply_options (options, c, p9_client_apply_addr_cb, p9_client_apply_option_cb);
}

static void p9_client_free(P9Client *c) {
	if (c) {
		r_socket_free (c->sock);
		free (c->host);
		free (c->port);
		free (c->path);
		free (c->uname);
		free (c->aname);
		free (c);
	}
}

static P9Client *p9_client_new(const char *options) {
	P9Client *c = R_NEW0 (P9Client);
	char *transport = p9_cfg_dup ("R2_FS_9FS_TRANSPORT", p9_cfg_transport, "tcp");
	c->transport = p9_transport_from_string (transport);
	free (transport);
	c->host = p9_cfg_dup ("R2_FS_9FS_HOST", p9_cfg_host, P9_DEFAULT_HOST);
	c->port = p9_cfg_dup ("R2_FS_9FS_PORT", p9_cfg_port, P9_DEFAULT_PORT);
	c->path = p9_cfg_dup ("R2_FS_9FS_PATH", p9_cfg_path, "");
	c->uname = p9_cfg_user ();
	c->aname = p9_cfg_dup ("R2_FS_9FS_ANAME", p9_cfg_aname, "");
	p9_client_apply_options (c, options);
	if (c->transport == P9_TRANSPORT_UNIX && R_STR_ISEMPTY (c->path) && R_STR_ISNOTEMPTY (c->host) && *c->host == '/') {
		p9_set_string (&c->path, c->host);
	}
	c->rootfid = 1;
	c->nextfid = c->rootfid;
	c->sock = r_socket_new (false);
	return c;
}

static P9File *p9_file_new(P9Client *c, ut32 fid) {
	P9File *pf = R_NEW0 (P9File);
	pf->client = c;
	pf->fid = fid;
	return pf;
}

static bool p9_parent_name(const char *path, char **parent, char **name) {
	char *p = r_str_trim_dup (path);
	if (!p) {
		return false;
	}
	r_str_trim_path (p);
	if (!*p || !strcmp (p, "/")) {
		free (p);
		return false;
	}
	char *slash = strrchr (p, '/');
	if (slash) {
		*slash++ = 0;
		if (!*slash) {
			free (p);
			return false;
		}
		*name = strdup (slash);
		*parent = *p? strdup (p): strdup ("/");
		free (p);
	} else {
		*parent = strdup ("/");
		*name = p;
	}
	if (!*parent || !*name || !strcmp (*name, ".") || !strcmp (*name, "..")) {
		R_FREE (*parent);
		R_FREE (*name);
		return false;
	}
	return true;
}

static bool p9_open_existing(P9Client *c, const char *path, ut8 mode, RFSFile *file, char **err) {
	ut32 fid = p9_next_fid (c);
	if (!p9_walk (c, c->rootfid, fid, path, err)) {
		return false;
	}
	P9Stat st = { 0 };
	bool ok = p9_stat (c, fid, &st, err);
	if (ok && p9_open (c, fid, mode, err)) {
		p9_file_fill (file, &st);
		file->ptr = p9_file_new (c, fid);
		p9_stat_free (&st);
		return true;
	}
	p9_stat_free (&st);
	char *clunk_err = NULL;
	p9_clunk (c, fid, &clunk_err);
	free (clunk_err);
	return false;
}

static bool p9_create_file(P9Client *c, const char *path, RFSFile *file, char **err) {
	char *parent = NULL;
	char *name = NULL;
	if (!p9_parent_name (path, &parent, &name)) {
		*err = strdup ("invalid path");
		return false;
	}
	ut32 fid = p9_next_fid (c);
	bool ok = p9_walk (c, c->rootfid, fid, parent, err);
	if (ok) {
		ok = p9_create (c, fid, name, 0666, P9_OWRITE | P9_OTRUNC, err);
	}
	free (parent);
	free (name);
	if (!ok) {
		char *clunk_err = NULL;
		p9_clunk (c, fid, &clunk_err);
		free (clunk_err);
		return false;
	}
	file->type = R_FS_FILE_TYPE_REGULAR;
	file->perm = 0666;
	file->size = 0;
	file->ptr = p9_file_new (c, fid);
	return true;
}

static RFSFile *fs_p9_open(RFSRoot *root, const char *path, bool create) {
	R_RETURN_VAL_IF_FAIL (root && root->ptr && path, NULL);
	P9Client *c = (P9Client *)root->ptr;
	RFSFile *file = r_fs_file_new (root, path);
	if (!file) {
		return NULL;
	}
	char *err = NULL;
	bool ok = false;
	if (create) {
		ok = p9_open_existing (c, path, P9_OWRITE | P9_OTRUNC, file, &err);
		if (!ok) {
			free (err);
			err = NULL;
			ok = p9_create_file (c, path, file, &err);
		}
	} else {
		ok = p9_open_existing (c, path, P9_OREAD, file, &err);
	}
	if (!ok) {
		if (err) {
			R_LOG_DEBUG ("%s", err);
		}
		free (err);
		r_fs_file_free (file);
		return NULL;
	}
	free (err);
	return file;
}

static int fs_p9_read(RFSFile *file, ut64 addr, int len) {
	R_RETURN_VAL_IF_FAIL (file && file->ptr && len >= 0, -1);
	P9File *pf = (P9File *)file->ptr;
	P9Client *c = pf->client;
	ut32 maxread = p9_max_read (c);
	if (!maxread) {
		return -1;
	}
	R_FREE (file->data);
	if (!len) {
		return 0;
	}
	file->data = malloc ((size_t)len);
	if (!file->data) {
		return -1;
	}
	int done = 0;
	while (done < len) {
		ut32 chunk = (ut32)R_MIN ((ut64)(len - done), (ut64)maxread);
		ut8 *data = NULL;
		ut32 dlen = 0;
		char *err = NULL;
		if (!p9_read_once (c, pf->fid, addr + done, chunk, &data, &dlen, &err)) {
			R_LOG_DEBUG ("%s", err? err: "read failed");
			free (err);
			free (data);
			break;
		}
		if (!dlen) {
			free (data);
			break;
		}
		memcpy (file->data + done, data, dlen);
		done += (int)dlen;
		free (data);
		if (dlen < chunk) {
			break;
		}
	}
	if (!done) {
		R_FREE (file->data);
	}
	file->size = done > 0? (ut32)done: 0;
	return done;
}

static int fs_p9_write(RFSFile *file, ut64 addr, const ut8 *data, int len) {
	R_RETURN_VAL_IF_FAIL (file && file->ptr && data && len >= 0, -1);
	P9File *pf = (P9File *)file->ptr;
	P9Client *c = pf->client;
	ut32 maxwrite = p9_max_write (c);
	if (!maxwrite) {
		return -1;
	}
	int done = 0;
	while (done < len) {
		ut32 chunk = (ut32)R_MIN ((ut64)(len - done), (ut64)maxwrite);
		ut32 wrote = 0;
		char *err = NULL;
		if (!p9_write_once (c, pf->fid, addr + done, data + done, chunk, &wrote, &err)) {
			R_LOG_DEBUG ("%s", err? err: "write failed");
			free (err);
			return done? done: -1;
		}
		free (err);
		if (!wrote) {
			break;
		}
		done += (int)wrote;
		if (wrote < chunk) {
			break;
		}
	}
	if (addr + done > file->size) {
		file->size = addr + done > UT32_MAX? UT32_MAX: (ut32)(addr + done);
	}
	return done;
}

static void fs_p9_close(RFSFile *file) {
	if (file && file->ptr) {
		P9File *pf = (P9File *)file->ptr;
		char *err = NULL;
		p9_clunk (pf->client, pf->fid, &err);
		free (err);
		free (pf);
		file->ptr = NULL;
	}
}

static RList *fs_p9_dir(RFSRoot *root, const char *path, R_UNUSED int view) {
	R_RETURN_VAL_IF_FAIL (root && root->ptr && path, NULL);
	P9Client *c = (P9Client *)root->ptr;
	ut32 fid = p9_next_fid (c);
	char *err = NULL;
	bool walked = p9_walk (c, c->rootfid, fid, path, &err);
	if (!walked || !p9_open (c, fid, P9_OREAD, &err)) {
		R_LOG_DEBUG ("%s", err? err: "directory open failed");
		if (walked) {
			char *clunk_err = NULL;
			p9_clunk (c, fid, &clunk_err);
			free (clunk_err);
		}
		free (err);
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)r_fs_file_free);
	if (!list) {
		p9_clunk (c, fid, &err);
		free (err);
		return NULL;
	}
	ut64 off = 0;
	ut32 maxread = p9_max_read (c);
	for (;;) {
		ut8 *data = NULL;
		ut32 dlen = 0;
		if (!p9_read_once (c, fid, off, maxread, &data, &dlen, &err)) {
			R_LOG_DEBUG ("%s", err? err: "directory read failed");
			free (err);
			r_list_free (list);
			list = NULL;
			break;
		}
		if (!dlen) {
			free (data);
			break;
		}
		size_t pos = 0;
		while (pos < dlen) {
			P9Stat st = { 0 };
			if (!p9_parse_stat_record (data, dlen, &pos, &st)) {
				p9_stat_free (&st);
				free (data);
				r_list_free (list);
				list = NULL;
				goto beach;
			}
			p9_append_file (list, &st);
			p9_stat_free (&st);
		}
		off += dlen;
		free (data);
	}
beach:
	p9_clunk (c, fid, &err);
	free (err);
	return list;
}

static bool fs_p9_unlink(RFSRoot *root, const char *path) {
	R_RETURN_VAL_IF_FAIL (root && root->ptr && path, false);
	P9Client *c = (P9Client *)root->ptr;
	ut32 fid = p9_next_fid (c);
	char *err = NULL;
	if (!p9_walk (c, c->rootfid, fid, path, &err)) {
		free (err);
		return false;
	}
	bool ok = p9_remove (c, fid, &err);
	free (err);
	return ok;
}

static bool fs_p9_mount(RFSRoot *root) {
	R_RETURN_VAL_IF_FAIL (root, false);
	P9Client *c = p9_client_new (root->options);
	if (!c || !c->sock) {
		p9_client_free (c);
		return false;
	}
	bool connected = false;
	switch (c->transport) {
	case P9_TRANSPORT_UDP:
		connected = r_socket_connect_udp (c->sock, c->host, c->port, 5);
		break;
	case P9_TRANSPORT_UNIX:
		connected = R_STR_ISNOTEMPTY (c->path) && r_socket_connect_unix (c->sock, c->path);
		break;
	case P9_TRANSPORT_TCP:
	default:
		connected = r_socket_connect_tcp (c->sock, c->host, c->port, 5);
		break;
	}
	if (!connected) {
		if (c->transport == P9_TRANSPORT_UNIX) {
			R_LOG_ERROR ("Cannot connect to 9fs server at unix:%s", c->path? c->path: "");
		} else {
			R_LOG_ERROR ("Cannot connect to 9fs server at %s:%s over %s",
				c->host? c->host: "", c->port? c->port: "", p9_transport_name (c->transport));
		}
		p9_client_free (c);
		return false;
	}
	char *err = NULL;
	if (!p9_client_version (c, &err) || !p9_client_attach (c, &err)) {
		R_LOG_ERROR ("Cannot mount 9fs: %s", err? err: "protocol error");
		free (err);
		p9_client_free (c);
		return false;
	}
	free (err);
	root->ptr = c;
	return true;
}

static void fs_p9_umount(RFSRoot *root) {
	if (root) {
		p9_client_free ((P9Client *)root->ptr);
		root->ptr = NULL;
	}
}

static void fs_p9_details(RFSRoot *root, RStrBuf *sb) {
	if (!root || !root->ptr || !sb) {
		return;
	}
	P9Client *c = (P9Client *)root->ptr;
	r_strbuf_appendf (sb, "Transport: %s\n", p9_transport_name (c->transport));
	if (c->transport == P9_TRANSPORT_UNIX) {
		r_strbuf_appendf (sb, "Server: unix:%s\n", c->path);
	} else {
		r_strbuf_appendf (sb, "Server: %s:%s\n", c->host, c->port);
	}
	r_strbuf_appendf (sb, "User: %s\n", c->uname);
	r_strbuf_appendf (sb, "Attach: %s\n", c->aname);
	r_strbuf_appendf (sb, "Msize: %u\n", (unsigned)c->msize);
}

static void p9_set_string(char **dst, const char *src) {
	R_FREE (*dst);
	*dst = strdup (src? src: "");
}

static bool p9_set_addr(const char *addr) {
	if (R_STR_ISEMPTY (addr)) {
		return false;
	}
	if (*addr == '/') {
		p9_set_string (&p9_cfg_transport, "unix");
		p9_set_string (&p9_cfg_path, addr);
		return true;
	}
	const char *host = addr;
	const char *port = NULL;
	char *tmp = NULL;
	if (r_str_startswith (addr, "tcp!") || r_str_startswith (addr, "udp!")) {
		p9_set_string (&p9_cfg_transport, *addr == 'u'? "udp": "tcp");
		host = addr + 4;
		port = strrchr (host, '!');
		if (!port || port == host) {
			return false;
		}
		tmp = r_str_ndup (host, port - host);
		host = tmp;
		port++;
	} else if (r_str_startswith (addr, "unix!")) {
		p9_set_string (&p9_cfg_transport, "unix");
		p9_set_string (&p9_cfg_path, addr + 5);
		return true;
	} else if (r_str_startswith (addr, "unix:")) {
		p9_set_string (&p9_cfg_transport, "unix");
		p9_set_string (&p9_cfg_path, addr + 5);
		return true;
	} else {
		port = strrchr (addr, ':');
		if (port && port != addr) {
			tmp = r_str_ndup (addr, port - addr);
			host = tmp;
			port++;
		}
	}
	if (R_STR_ISNOTEMPTY (host)) {
		p9_set_string (&p9_cfg_host, host);
	}
	if (R_STR_ISNOTEMPTY (port)) {
		p9_set_string (&p9_cfg_port, port);
	}
	free (tmp);
	return true;
}

static void p9_apply_global_option(const char *key, const char *value) {
	if (!r_str_casecmp (key, "transport") || !r_str_casecmp (key, "proto")) {
		p9_set_string (&p9_cfg_transport, value);
	} else if (!r_str_casecmp (key, "host") || !r_str_casecmp (key, "server")) {
		p9_set_string (&p9_cfg_host, value);
	} else if (!r_str_casecmp (key, "port") || !r_str_casecmp (key, "service")) {
		p9_set_string (&p9_cfg_port, value);
	} else if (!r_str_casecmp (key, "socket")) {
		p9_set_string (&p9_cfg_transport, "unix");
		p9_set_string (&p9_cfg_path, value);
	} else if (!r_str_casecmp (key, "path")) {
		p9_set_string (&p9_cfg_path, value);
	} else if (!r_str_casecmp (key, "user") || !r_str_casecmp (key, "uname")) {
		p9_set_string (&p9_cfg_uname, value);
	} else if (!r_str_casecmp (key, "aname") || !r_str_casecmp (key, "attach")) {
		p9_set_string (&p9_cfg_aname, value);
	} else if (!r_str_casecmp (key, "addr") || !r_str_casecmp (key, "remote")) {
		p9_set_addr (value);
	}
}

static void p9_apply_global_addr_cb(void *user, const char *addr) {
	(void)user;
	p9_set_addr (addr);
}

static void p9_apply_global_option_cb(void *user, const char *key, const char *value) {
	(void)user;
	p9_apply_global_option (key, value);
}

static void p9_apply_global_options(const char *options) {
	p9_apply_options (options, NULL, p9_apply_global_addr_cb, p9_apply_global_option_cb);
}

static bool fs_p9_cmd(RFS *fs, const char *cmd) {
	R_RETURN_VAL_IF_FAIL (fs && cmd, false);
	if (strncmp (cmd, "9fs", 3)) {
		return false;
	}
	const char *arg = cmd + 3;
	if (*arg && *arg != '?' && arg == r_str_trim_head_ro (arg)) {
		return false;
	}
	arg = r_str_trim_head_ro (arg);
	if (*arg == '?') {
		R_LOG_INFO ("Usage: m:9fs [host] [port] [user] [aname]");
		R_LOG_INFO ("       m:9fs transport=tcp,host=127.0.0.1,port=9999");
		R_LOG_INFO ("       m:9fs tcp!host!port | udp!host!port | unix!/path");
		return true;
	}
	if (!*arg) {
		R_LOG_INFO ("9fs transport=%s,host=%s,port=%s,path=%s",
			p9_cfg_transport? p9_cfg_transport: "tcp",
			p9_cfg_host? p9_cfg_host: P9_DEFAULT_HOST,
			p9_cfg_port? p9_cfg_port: P9_DEFAULT_PORT,
			p9_cfg_path? p9_cfg_path: "");
		return true;
	}
	if (strchr (arg, '=')) {
		p9_apply_global_options (arg);
		return true;
	}
	int argc = 0;
	char **argv = r_str_argv (arg, &argc);
	if (!argv) {
		return true;
	}
	if (argc == 1) {
		p9_set_addr (argv[0]);
	} else {
		p9_set_string (&p9_cfg_host, argv[0]);
		if (argc > 1) {
			p9_set_string (&p9_cfg_port, argv[1]);
		}
	}
	if (argc > 2) {
		p9_set_string (&p9_cfg_uname, argv[2]);
	}
	if (argc > 3) {
		p9_set_string (&p9_cfg_aname, argv[3]);
	}
	r_str_argv_free (argv);
	return true;
}

RFSPlugin r_fs_plugin_p9 = {
	.meta = {
		.name = "9fs",
		.desc = "Plan 9 9P filesystem over RSocket",
		.license = "LGPL3",
	},
	.open = fs_p9_open,
	.read = fs_p9_read,
	.write = fs_p9_write,
	.close = fs_p9_close,
	.dir = fs_p9_dir,
	.unlink = fs_p9_unlink,
	.mount = fs_p9_mount,
	.umount = fs_p9_umount,
	.details = fs_p9_details,
	.cmd = fs_p9_cmd,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_FS,
	.data = &r_fs_plugin_p9,
	.version = R2_VERSION
};
#endif
