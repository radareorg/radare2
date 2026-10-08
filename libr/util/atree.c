/* radare - LGPL - Copyright 2026 - pancake */

#include <r_util.h>

typedef struct {
	RStrBuf output;
	RStrBuf prefix;
	RTreeNodeLabelCb label;
	void *user;
	bool failed;
} AsciiTreeContext;

static void atree_visit(RTreeNode *node, RTreeVisitor *visitor) {
	AsciiTreeContext *ctx = visitor->user;
	if (ctx->failed) {
		return;
	}
	const char *label = ctx->label? ctx->label (node, ctx->user): node->data;
	if (!node->parent) {
		ctx->failed = !r_strbuf_appendf (&ctx->output, "%s\n", r_str_get (label));
		return;
	}
	ut32 prefix_length;
	if (node->depth < 1 || r_mul_overflow_ut32 (node->depth - 1, 4, &prefix_length)
		|| prefix_length > INT_MAX) {
		ctx->failed = true;
		return;
	}
	r_strbuf_slice (&ctx->prefix, 0, prefix_length);
	bool last = r_list_last (node->parent->children) == node;
	ctx->failed = !r_strbuf_appendf (&ctx->output, "%s%s%s\n", r_strbuf_get (&ctx->prefix),
		last? "`-- ": "|-- ", r_str_get (label))
		|| !r_strbuf_append (&ctx->prefix, last? "    ": "|   ");
}

R_API R_OWNED char *r_tree_to_ascii(RTree *tree, RTreeNodeLabelCb R_NULLABLE label, void *user) {
	R_RETURN_VAL_IF_FAIL (tree, NULL);
	AsciiTreeContext ctx = { .label = label, .user = user };
	r_strbuf_init (&ctx.output);
	r_strbuf_init (&ctx.prefix);
	RTreeVisitor visitor = { .pre_visit = atree_visit, .user = &ctx };
	r_tree_dfs (tree, &visitor);
	r_strbuf_fini (&ctx.prefix);
	if (ctx.failed) {
		r_strbuf_fini (&ctx.output);
		return NULL;
	}
	return r_strbuf_drain_nofree (&ctx.output);
}
