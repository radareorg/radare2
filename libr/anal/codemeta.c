/* radare2 - LGPL - Copyright 2020-2025 - nimmumanoj, pancake */

#include <r_core.h>
#include <r_codemeta.h>

R_API RCodeMetaItem *r_codemeta_item_clone(RCodeMetaItem *code) {
	R_RETURN_VAL_IF_FAIL (code, NULL);
	RCodeMetaItem *mi = r_mem_dup (code, sizeof (RCodeMetaItem));
	switch (mi->type) {
	case R_CODEMETA_TYPE_FUNCTION_NAME:
		mi->reference.name = strdup (mi->reference.name);
		break;
	case R_CODEMETA_TYPE_LOCAL_VARIABLE:
	case R_CODEMETA_TYPE_FUNCTION_PARAMETER:
		mi->variable.name = strdup (mi->variable.name);
		break;
	case R_CODEMETA_TYPE_CONSTANT_VARIABLE:
	case R_CODEMETA_TYPE_OFFSET:
	case R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT:
	case R_CODEMETA_TYPE_GLOBAL_VARIABLE:
		break;
	}
	return mi;
}

R_API RCodeMeta *r_codemeta_clone(RCodeMeta *code) {
	R_RETURN_VAL_IF_FAIL (code, NULL);
	RCodeMeta *r = r_codemeta_new (code->code);
	RCodeMetaItem *mi;
	r_vector_foreach (&code->annotations, mi) {
		r_codemeta_add_item (r, r_codemeta_item_clone (mi));
	}
	return r;
}

R_API RCodeMeta * R_NONNULL r_codemeta_new(const char *code) {
	R_RETURN_VAL_IF_FAIL (code, NULL);
	RCodeMeta *r = R_NEW0 (RCodeMeta);
	r->tree = r_crbtree_new (NULL);
	r->code = strdup (code);
	r_vector_init (&r->annotations, sizeof (RCodeMetaItem),
			(RVectorFree)r_codemeta_item_fini, NULL);
	return r;
}

R_API RCodeMetaItem * R_NONNULL r_codemeta_item_new(void) {
	return R_NEW0 (RCodeMetaItem);
}

R_API void r_codemeta_item_free(RCodeMetaItem *mi) {
	if (R_LIKELY (mi)) {
		r_codemeta_item_fini (mi);
		free (mi);
	}
}

R_API void r_codemeta_item_fini(RCodeMetaItem *mi) {
	R_RETURN_IF_FAIL (mi);
	switch (mi->type) {
	case R_CODEMETA_TYPE_FUNCTION_NAME:
		free (mi->reference.name);
		break;
	case R_CODEMETA_TYPE_LOCAL_VARIABLE:
	case R_CODEMETA_TYPE_FUNCTION_PARAMETER:
		free (mi->variable.name);
		break;
	case R_CODEMETA_TYPE_CONSTANT_VARIABLE:
	case R_CODEMETA_TYPE_OFFSET:
	case R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT:
	case R_CODEMETA_TYPE_GLOBAL_VARIABLE:
		break;
	}
}

R_API bool r_codemeta_item_is_reference(RCodeMetaItem *mi) {
	R_RETURN_VAL_IF_FAIL (mi, false);
	return (mi->type == R_CODEMETA_TYPE_GLOBAL_VARIABLE || mi->type == R_CODEMETA_TYPE_CONSTANT_VARIABLE || mi->type == R_CODEMETA_TYPE_FUNCTION_NAME);
}

R_API bool r_codemeta_item_is_variable(RCodeMetaItem *mi) {
	R_RETURN_VAL_IF_FAIL (mi, false);
	return (mi->type == R_CODEMETA_TYPE_LOCAL_VARIABLE || mi->type == R_CODEMETA_TYPE_FUNCTION_PARAMETER);
}

R_API void r_codemeta_free(RCodeMeta *code) {
	if (R_LIKELY (code)) {
		r_vector_clear (&code->annotations);
		r_crbtree_free (code->tree);
		r_free (code->code);
		r_free (code);
	}
}

static int cmp_ins(void *incoming, void *in, void *user) {
	RCodeMetaItem *mi = in;
	RCodeMetaItem *mi2 = incoming;
	const size_t mid = mi->start + (mi->end - mi->start) / 2;	// this is buggy since 2/2 = 1/2 in C
	const size_t mid2 = mi2->start + (mi2->end - mi2->start) / 2;
	if (mid > mid2) {
		return -1;
	}
	if (mid < mid2) {
		return 1;
	}
	const ut32 mod = (mi->end - mi->start) & 0x1;	// this fixes the buggy
	const ut32 mod2 = (mi2->end - mi2->start) & 0x1;
	if (mod > mod2) {
		return -1;
	}
	if (mod < mod2) {
		return 1;
	}
	return ((int)mi2->type) - ((int)mi->type);	// avoid weird things
}

// cmp to find the lowest mid, that is bigger than or equal to search_mid
// consider adding mod-bit to search_mid
static int cmp_find_min_mid(void *incoming, void *in, void *user) {
	RCodeMetaItem **min = (RCodeMetaItem **)user;
	RCodeMetaItem *mi = (RCodeMetaItem *)in;
	size_t *search_mid = (size_t *)incoming;
	const size_t mid = mi->start + (mi->end - mi->start) / 2;
	if (mid > search_mid[0]) {
		if (!min[0]) {
			min[0] = mi;
			return -1;
		}
		const size_t min_mid = min[0]->start + (min[0]->end - min[0]->start) / 2;
		if (mid < min_mid) {
			min[0] = mi;
		} else if (mid == min_mid) {
			const ut32 mod = (mi->end - mi->start) & 0x1;
			const ut32 min_mod = (min[0]->end - min[0]->start) & 0x1;
			if (mod < min_mod) {
				min[0] = mi;
			}
		}
		return -1;
	}
	if (mid == search_mid[0]) {
		min[0] = mi;
		return 0;
	}
	return 1;
}

R_API void r_codemeta_add_item(RCodeMeta *code, RCodeMetaItem *mi) {
	R_RETURN_IF_FAIL (code && mi);
	r_vector_push (&code->annotations, mi);
	r_crbtree_insert (code->tree, mi, cmp_ins, NULL);
}

R_API RPVector *r_codemeta_at(RCodeMeta *code, size_t offset) {
	R_RETURN_VAL_IF_FAIL (code, NULL);
	return r_codemeta_in (code, offset, offset + 1);
}

R_API RPVector *r_codemeta_in(RCodeMeta *code, size_t start, size_t end) {
	R_RETURN_VAL_IF_FAIL (code, NULL);
	RPVector *r = r_pvector_new (NULL);
	if (!r) {
		return NULL;
	}
	size_t search_start = start / 2;
	RCodeMetaItem *min = NULL;
	r_crbtree_find (code->tree, &search_start, cmp_find_min_mid, &min);
	if (min) {
		const size_t end_mid = (end - 1) + ((SIZE_MAX - end - 1) / 2);
		RRBNode *node = r_crbtree_find_node (code->tree, min, cmp_ins, NULL);	//get node for min
		RRBNode *prev = r_rbnode_prev (node);
		while (prev) {
			RCodeMetaItem *mi = (RCodeMetaItem *)prev->data;
			if (mi->end <= start) {
				break;
			}
			node = prev;
			prev = r_rbnode_prev (node);
		}
		while (node) {
			RCodeMetaItem *mi = (RCodeMetaItem *)node->data;
			if (!(start >= mi->end || end < mi->start)) {
				r_pvector_push (r, mi);
			}
			node = r_rbnode_next (node);
			if (node) {
				mi = (RCodeMetaItem *)node->data;
				const size_t mi_mid = mi->start + (mi->end - mi->start) / 2;
				if (end_mid < mi_mid) {
					break;
				}
			}
		}
	}
	return r;
}

R_API RVector *r_codemeta_line_offsets(RCodeMeta *code) {
	R_RETURN_VAL_IF_FAIL (code, NULL);
	RVector *r = r_vector_new (sizeof (ut64), NULL, NULL);
	if (!r) {
		return NULL;
	}
	size_t cur = 0;
	size_t len = strlen (code->code);
	do {
		char *next = strchr (code->code + cur, '\n');
		size_t next_i = next? (next - code->code) + 1: len;
		RPVector *annotations = r_codemeta_in (code, cur, next_i);
		ut64 offset = UT64_MAX;
		void **it;
		r_pvector_foreach (annotations, it) {
			RCodeMetaItem *mi = *it;
			if (mi->type != R_CODEMETA_TYPE_OFFSET) {
				continue;
			}
			offset = mi->offset.offset;
			break;
		}
		r_vector_push (r, &offset);
		cur = next_i;
		r_pvector_free (annotations);
	} while (cur < len);
	return r;
}

#define PALETTE(x) (cons && cons->context->pal.x) ? cons->context->pal.x
#define PRINT_COLOR(x) \
	do { \
		if (cons && cons->context && cons->context->color_mode) { \
			r_strbuf_appendf (sb, "%s", (x)); \
		} \
	} while (0)

/**
 * @param width maximum nibbles per address
 */
static void print_offset_in_binary_line_bar(RStrBuf *sb, RCodeMeta *code, ut64 offset, size_t width, RCons *cons) {
	if (width < 8) {
		width = 8;
	}
	if (width > 16) {
		width = 16;
	}
	width -= 8;

	r_strbuf_append (sb, "    ");
	if (offset == UT64_MAX) {
		r_strbuf_append (sb, "          ");
		while (width > 0) {
			r_strbuf_append (sb, " ");
			width--;
		}
	} else {
		PRINT_COLOR (PALETTE (addr) : Color_GREEN);
		r_strbuf_appendf (sb, "0x%08" PFMT64x, offset);
		PRINT_COLOR (Color_RESET);
	}
	r_strbuf_append (sb, "    |");
}

static void print_disasm_in_binary_line_bar(RStrBuf *sb, RCodeMeta *code, ut64 offset, size_t width, RAnal *anal) {
	width = 40;
	RCore *core = NULL;
	RCons *cons = NULL;
	if (anal && anal->coreb.core) {
		core = anal->coreb.core;
		cons = core->cons;
	} else {
		R_LOG_WARN ("No core for codemeta");
	}
	r_strbuf_append (sb, "    ");
	if (offset == UT64_MAX) {
		r_strbuf_pad (sb, ' ', width);
	} else {
		if (core) {
			char *c = r_str_newf ("pid 1 @ 0x%" PFMT64x " @e:asm.flags=0@e:asm.lines=0@e:asm.bytes=0", offset);
			char *res = anal->coreb.cmdStrF (core, c);
			free (c);
			r_str_trim (res);
			int w = r_str_ansi_len (res);
			r_strbuf_append (sb, res);
			if (w < width) {
				r_strbuf_pad (sb, ' ', width - w);
			} else {
				char *p = (char *)r_str_ansi_chrn (res, width);
				if (p) {
					*p = 0;
				}
			}
			free (res);
		} else {
			PRINT_COLOR (PALETTE (addr) : Color_GREEN);
			r_strbuf_appendf (sb, "0x%08" PFMT64x, offset);
			PRINT_COLOR (Color_RESET);
			r_strbuf_pad (sb, ' ', width - 11);
		}
	}
	r_strbuf_append (sb, "    |");
}

static char *r_codemeta_print_internal(RCodeMeta *code, RVector *line_offsets, RAnal *anal, bool doprint) {
	if (code->annotations.len == 0) {
		return r_str_newf ("%s\n", code->code);
	}

	RStrBuf *sb = r_strbuf_new ("");

	size_t cur = 0;
	size_t line_idx = 0;
	size_t len = strlen (code->code);

	size_t offset_width = 0;
	if (line_offsets) {
		ut64 *offset;
		ut64 offset_max = 0;
		r_vector_foreach (line_offsets, offset) {
			if (*offset != UT64_MAX && *offset > offset_max) {
				offset_max = *offset;
			}
		}
		while (offset_max) {
			offset_width += 1;
			offset_max >>= 4;
		}
		if (offset_width < 4) {
			offset_width = 4;
		}
	}

	RCore *core = NULL;
	RCons *cons = NULL;
	if (anal && anal->coreb.core) {
		core = anal->coreb.core;
		cons = core->cons;
	} else {
		R_LOG_WARN ("No core for codemeta");
	}
	RCodeMetaItem *annotation;
	r_vector_foreach (&code->annotations, annotation) {
		if (annotation->type != R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT) {
			continue;
		}

		// (1/3)
		// now we have a syntax highlighting annotation.
		// pick a suitable color for it.
		const char *color = Color_RESET;
		switch (annotation->syntax_highlight.type) {
		case R_SYNTAX_HIGHLIGHT_TYPE_COMMENT:
			color = PALETTE (comment)
			    : Color_WHITE;
			break;
		case R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD:
			color = PALETTE (pop)
			    : Color_MAGENTA;
			break;
		case R_SYNTAX_HIGHLIGHT_TYPE_DATATYPE:
			color = PALETTE (var_type)
			    : Color_BLUE;
			break;
		case R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME:
			color = PALETTE (fname)
			    : Color_RED;
			break;
		case R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE:
			color = PALETTE (num)
			    : Color_YELLOW;
			break;
		default:
			break;
		}

		// (2/3)
		// the chunk before the syntax highlighting annotation should not be colored
		for (; cur < annotation->start && cur < len; cur++) {
			// if we are starting a new line and we are printing with offsets
			// we need to prepare the bar with offsets on the left handside before that
			if (line_offsets && (cur == 0 || code->code[cur - 1] == '\n')) {
				ut64 offset = 0;
				if (line_idx < line_offsets->len) {
					offset = *(ut64 *)r_vector_index_ptr (line_offsets, line_idx);
				}
				if (doprint) {
					print_disasm_in_binary_line_bar (sb, code, offset, offset_width, anal);
				} else {
					print_offset_in_binary_line_bar (sb, code, offset, offset_width, cons);
				}
				line_idx++;
			}
			r_strbuf_appendf (sb, "%c", code->code[cur]);
		}

		// (3/3)
		// everything in between the "start" and the "end" inclusive should be highlighted
		PRINT_COLOR (color);
		for (; cur < annotation->end && cur < len; cur++) {
			// if we are starting a new line and we are printing with offsets
			// we need to prepare the bar with offsets on the left handside before that
			if (line_offsets && (cur == 0 || code->code[cur - 1] == '\n')) {
				ut64 offset = 0;
				if (line_idx < line_offsets->len) {
					offset = *(ut64 *)r_vector_index_ptr (line_offsets, line_idx);
				}
				PRINT_COLOR (Color_RESET);
				if (doprint) {
					print_disasm_in_binary_line_bar (sb, code, offset, offset_width, anal);
				} else {
					print_offset_in_binary_line_bar (sb, code, offset, offset_width, cons);
				}
				PRINT_COLOR (color);
				line_idx++;
			}
			r_strbuf_appendf (sb, "%c", code->code[cur]);
		}
		PRINT_COLOR (Color_RESET);
	}
	// the rest of the decompiled code should be printed
	// without any highlighting since we don't have any annotations left
	for (; cur < len; cur++) {
		// if we are starting a new line and we are printing with offsets
		// we need to prepare the bar with offsets on the left handside before that
		if (line_offsets && (cur == 0 || code->code[cur - 1] == '\n')) {
			ut64 offset = 0;
			if (line_idx < line_offsets->len) {
				offset = *(ut64 *)r_vector_index_ptr (line_offsets, line_idx);
			}
			if (doprint) {
				print_disasm_in_binary_line_bar (sb, code, offset, offset_width, anal);
			} else {
				print_offset_in_binary_line_bar (sb, code, offset, offset_width, cons);
			}
			line_idx++;
		}
		r_strbuf_appendf (sb, "%c", code->code[cur]);
	}
	return r_strbuf_drain (sb);
}

R_API char *r_codemeta_print_disasm(RCodeMeta *code, RVector *line_offsets, void *anal) {
	return r_codemeta_print_internal (code, line_offsets, anal, true);
}

R_API char *r_codemeta_print2(RCodeMeta *code, RVector *line_offsets, void *anal) {
	return r_codemeta_print_internal (code, line_offsets, anal, false);
}

// TODO rename R_API char *r_codemeta_print_offsets(RCodeMeta *code, RVector *line_offsets, bool d) {
R_API char *r_codemeta_print(RCodeMeta *code, RVector *line_offsets) {
	R_LOG_DEBUG ("RCodeMetaPrint is deprecated: use RCodeMetaPrint2 instead");
	return r_codemeta_print_internal (code, line_offsets, NULL, false);
}

static bool foreach_offset_annotation(void *user, const ut64 offset, const void *val) {
	struct { RCodeMeta *code; RStrBuf *sb; } *data = user;
	const RCodeMetaItem *annotation = val;
	char *b64statement = r_base64_encode_dyn ((const ut8*)data->code->code + annotation->start, annotation->end - annotation->start);
	r_strbuf_appendf (data->sb, "CCu base64:%s @ 0x%" PFMT64x "\n", b64statement, annotation->offset.offset);
	free (b64statement);
	return true;
}

R_API char *r_codemeta_print_comment_cmds(RCodeMeta *code) {
	RCodeMetaItem *annotation;
	HtUP *ht = ht_up_new0 ();
	r_vector_foreach (&code->annotations, annotation) {
		if (annotation->type != R_CODEMETA_TYPE_OFFSET) {
			continue;
		}
		// choose the "best" annotation at a single offset
		RCodeMetaItem *prev_annot = ht_up_find (ht, annotation->offset.offset, NULL);
		if (prev_annot) {
			if (annotation->end - annotation->start < prev_annot->end - prev_annot->start) {
				continue;
			}
		}
		ht_up_update (ht, annotation->offset.offset, annotation);
	}
	struct { RCodeMeta *code; RStrBuf *sb; } data;
	data.code = code;
	data.sb = r_strbuf_new ("");
	ht_up_foreach (ht, foreach_offset_annotation, &data);
	ht_up_free (ht);
	return r_strbuf_drain (data.sb);
}

R_API char *r_codemeta_print_json(RCodeMeta *code) {
	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}

	pj_o (pj);
	pj_ks (pj, "code", code->code);

	pj_k (pj, "annotations");
	pj_a (pj);

	char *type_str;
	RCodeMetaItem *annotation;
	r_vector_foreach (&code->annotations, annotation) {
		pj_o (pj);
		pj_kn (pj, "start", (ut64)annotation->start);
		pj_kn (pj, "end", (ut64)annotation->end);
		switch (annotation->type) {
		case R_CODEMETA_TYPE_OFFSET:
			pj_ks (pj, "type", "offset");
			pj_kn (pj, "offset", annotation->offset.offset);
			break;
		case R_CODEMETA_TYPE_FUNCTION_NAME:
			pj_ks (pj, "type", "function_name");
			pj_ks (pj, "name", annotation->reference.name);
			pj_kn (pj, "offset", annotation->reference.offset);
			break;
		case R_CODEMETA_TYPE_GLOBAL_VARIABLE:
			pj_ks (pj, "type", "global_variable");
			pj_kn (pj, "offset", annotation->reference.offset);
			break;
		case R_CODEMETA_TYPE_CONSTANT_VARIABLE:
			pj_ks (pj, "type", "constant_variable");
			pj_kn (pj, "offset", annotation->reference.offset);
			break;
		case R_CODEMETA_TYPE_LOCAL_VARIABLE:
			pj_ks (pj, "type", "local_variable");
			pj_ks (pj, "name", annotation->variable.name);
			break;
		case R_CODEMETA_TYPE_FUNCTION_PARAMETER:
			pj_ks (pj, "type", "function_parameter");
			pj_ks (pj, "name", annotation->variable.name);
			break;
		case R_CODEMETA_TYPE_SYNTAX_HIGHLIGHT:
			pj_ks (pj, "type", "syntax_highlight");
			type_str = NULL;
			switch (annotation->syntax_highlight.type) {
			case R_SYNTAX_HIGHLIGHT_TYPE_KEYWORD:
				type_str = "keyword";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_COMMENT:
				type_str = "comment";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_DATATYPE:
				type_str = "datatype";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_NAME:
				type_str = "function_name";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_FUNCTION_PARAMETER:
				type_str = "function_parameter";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_LOCAL_VARIABLE:
				type_str = "local_variable";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_CONSTANT_VARIABLE:
				type_str = "constant_variable";
				break;
			case R_SYNTAX_HIGHLIGHT_TYPE_GLOBAL_VARIABLE:
				type_str = "global_variable";
				break;
			}
			if (type_str) {
				pj_ks (pj, "syntax_highlight", type_str);
			}
			break;
		}
		pj_end (pj);
	}
	pj_end (pj);
	pj_end (pj);
	return pj_drain (pj);
}
