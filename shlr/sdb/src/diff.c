/* sdb - MIT - Copyright 2019 - thestr4ng3r */

#include "sdb.h"

SDB_API int sdb_diff_format(char *str, int size, const SdbDiff *diff) {
	int r = 0;
#define APPENDF(...) do { \
		int sr = snprintf (str, size, __VA_ARGS__); \
		if (sr < 0) { \
			return sr; \
		} \
		r += sr; \
		if (sr >= size) { \
			/* no space left, only measure from now on */ \
			str = NULL; \
			size = 0; \
		} else { \
			str += sr; \
			size -= sr; \
		} \
	} while(0)

	APPENDF ("%c%s ", diff->add ? '+' : '-', diff->v ? "  " : "NS");

	SdbListIter *it;
	const char *component;
	ls_foreach (diff->path, it, component) {
		APPENDF ("%s/", component);
	}

	if (diff->v) {
		APPENDF ("%s=%s", diff->k, diff->v);
	} else {
		APPENDF ("%s", diff->k);
	}

#undef APPENDF
	return r;
}

typedef struct sdb_diff_ctx_t {
	Sdb *a;
	Sdb *b;
	bool equal;
	SdbList *path;
	SdbDiffCallback cb;
	void *cb_user;
} SdbDiffCtx;

#define DIFF(ctx, c, ret) do { \
	(ctx)->equal = false; \
	if ((ctx)->cb) { \
		c \
	} else { \
		/* we already know it's not equal and don't care about the rest of the diff */ \
		return ret; \
	} \
} while(0)


static void sdb_diff_report_ns(SdbDiffCtx *ctx, SdbNs *ns, bool add) {
	SdbDiff diff = { ctx->path, ns->name, NULL, add };
	ctx->cb (&diff, ctx->cb_user);
}

static void sdb_diff_report_kv(SdbDiffCtx *ctx, const char *k, const char *v, bool add) {
	SdbDiff diff = { ctx->path, k, v, add };
	ctx->cb (&diff, ctx->cb_user);
}

typedef struct sdb_diff_kv_cb_ctx {
	SdbDiffCtx *ctx;
	bool add;
} SdbDiffKVCbCtx;

static int sdb_diff_report_kv_cb(void *user, const char *k, const char *v) {
	const SdbDiffKVCbCtx *ctx = user;
	sdb_diff_report_kv (ctx->ctx, k, v, ctx->add);
	return true;
}

/**
 * just report everything from sdb to buf with prefix
 */
static void sdb_diff_report(SdbDiffCtx *ctx, Sdb *sdb, bool add) {
	SdbListIter *it;
	SdbNs *ns;
	ls_foreach (sdb->ns, it, ns) {
		sdb_diff_report_ns (ctx, ns, add);
		ls_push (ctx->path, ns->name);
		sdb_diff_report (ctx, ns->sdb, add);
		ls_pop (ctx->path);
	}
	SdbDiffKVCbCtx cb_ctx = { ctx, add };
	sdb_foreach (sdb, sdb_diff_report_kv_cb, &cb_ctx);
}

static int sdb_diff_kv_cb(void *user, const char *k, const char *v) {
	const SdbDiffKVCbCtx *ctx = user;
	Sdb *other = ctx->add ? ctx->ctx->a : ctx->ctx->b;
	const char *other_val = sdb_get (other, k, NULL);
	if (!other_val || !*other_val) {
		DIFF (ctx->ctx,
			sdb_diff_report_kv (ctx->ctx, k, v, ctx->add);
		, false);
	} else if (!ctx->add && strcmp (v, other_val) != 0) {
		DIFF (ctx->ctx,
			sdb_diff_report_kv (ctx->ctx, k, v, false);
			sdb_diff_report_kv (ctx->ctx, k, other_val, true);
		, false);
	}
	return true;
}

static void sdb_diff_ctx(SdbDiffCtx *ctx) {
	SdbListIter *it;
	SdbNs *ns;
	ls_foreach (ctx->a->ns, it, ns) {
		Sdb *b_ns = sdb_ns (ctx->b, ns->name, false);
		if (!b_ns) {
			DIFF (ctx,
				sdb_diff_report_ns (ctx, ns, false);
				ls_push (ctx->path, ns->name);
				sdb_diff_report (ctx, ns->sdb, false);
				ls_pop (ctx->path);
			,);
			continue;
		}
		Sdb *a = ctx->a;
		Sdb *b = ctx->b;
		ctx->a = ns->sdb;
		ctx->b = b_ns;
		ls_push (ctx->path, ns->name);
		sdb_diff_ctx (ctx);
		ls_pop (ctx->path);
		ctx->a = a;
		ctx->b = b;
	}
	ls_foreach (ctx->b->ns, it, ns) {
		if (!sdb_ns (ctx->a, ns->name, false)) {
			DIFF (ctx,
				sdb_diff_report_ns (ctx, ns, true);
				ls_push (ctx->path, ns->name);
				sdb_diff_report (ctx, ns->sdb, true);
				ls_pop (ctx->path);
			,);
		}
	}
	SdbDiffKVCbCtx kv_ctx = { ctx, false };
	if (!sdb_foreach (ctx->a, sdb_diff_kv_cb, &kv_ctx)) {
		return;
	}
	kv_ctx.add = true;
	sdb_foreach (ctx->b, sdb_diff_kv_cb, &kv_ctx);
}

SDB_API bool sdb_diff(Sdb *a, Sdb *b, SdbDiffCallback cb, void *cb_user) {
	SdbDiffCtx ctx;
	ctx.a = a;
	ctx.b = b;
	ctx.equal = true;
	ctx.cb = cb;
	ctx.cb_user = cb_user;
	ctx.path = ls_new ();
	if (!ctx.path) {
		return false;
	}
	sdb_diff_ctx (&ctx);
	ls_free (ctx.path);
	return ctx.equal;
}
