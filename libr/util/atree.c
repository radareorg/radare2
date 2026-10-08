/* radare - LGPL - Copyright 2026 - pancake */

#include <r_util.h>

typedef struct {
	RStrBuf output;
	RStrBuf continuation;
	RTreeNodeLabelCb label;
	void *user;
	bool utf8;
	bool failed;
} ATreeContext;

static void atree_visit(RTreeNode *node, RTreeVisitor *visitor) {
	ATreeContext *ctx = visitor->user;
	if (ctx->failed) {
		return;
	}
	const char *label = ctx->label? ctx->label (node, ctx->user): node->data;
	if (!node->parent) {
		ctx->failed = !r_strbuf_appendf (&ctx->output, "%s\n", r_str_get (label));
		return;
	}
	if (node->depth < 1) {
		ctx->failed = true;
		return;
	}
	r_strbuf_slice (&ctx->continuation, 0, node->depth - 1);
	const char *continuation = r_strbuf_get (&ctx->continuation);
	int i;
	for (i = 0; i < node->depth - 1; i++) {
		const char *prefix = continuation[i] == '|'? (ctx->utf8? "│   ": "|   "): "    ";
		if (!r_strbuf_append (&ctx->output, prefix)) {
			ctx->failed = true;
			return;
		}
	}
	bool last = r_list_last (node->parent->children) == node;
	const char *branch = ctx->utf8? (last? "└── ": "├── "): (last? "`-- ": "|-- ");
	ctx->failed = !r_strbuf_appendf (&ctx->output, "%s%s\n", branch, r_str_get (label))
		|| !r_strbuf_append (&ctx->continuation, last? " ": "|");
}

R_API R_OWNED char *r_tree_to_string(RTree *tree, RTreeNodeLabelCb R_NULLABLE label, void *user, bool utf8) {
	R_RETURN_VAL_IF_FAIL (tree, NULL);
	ATreeContext ctx = { .label = label, .user = user, .utf8 = utf8 };
	r_strbuf_init (&ctx.output);
	r_strbuf_init (&ctx.continuation);
	RTreeVisitor visitor = { .pre_visit = atree_visit, .user = &ctx };
	r_tree_dfs (tree, &visitor);
	r_strbuf_fini (&ctx.continuation);
	if (ctx.failed) {
		r_strbuf_fini (&ctx.output);
		return NULL;
	}
	return r_strbuf_drain_nofree (&ctx.output);
}
