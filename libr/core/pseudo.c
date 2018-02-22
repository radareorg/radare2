/* radare - LGPL - Copyright 2015-2017 - pancake */

#include <r_core.h>
#define TYPE_NONE 0
#define TYPE_STR 1
#define TYPE_SYM 2
#define IS_ALPHA(x) (IS_UPPER(x) || IS_LOWER(x))
#define IS_STRING(x,y) ((x)+3<end && *x == 's' && *((x)+1) == 't' && *((x)+2) == 'r' && *((x)+3) == '.')
#define IS_SYMBOL(x,y) ((x)+3<end && *x == 's' && *((x)+1) == 'y' && *((x)+2) == 'm' && *((x)+3) == '.')

typedef struct _find_ctx {
	char *comment;
	char *left;
	char *right;
	char *linebegin;
	int leftlen;
	int rightlen;
	int leftpos;
	int leftcolor;
	int commentcolor;
	int rightcolor;
	int linecount;
	int type;
} RFindCTX;

static void find_and_change (char* in, int len) {
	// just to avoid underflows.. len can't be < then len(padding).
	if (!in || len < 1) {
		return;
	}
	char *end;
	RFindCTX ctx = {0};
	end = in + len;
//	type = TYPE_NONE;
	for (ctx.linebegin = in; in < end; ++in) {
		if (*in == '\n' || !*in) {
			if (ctx.type == TYPE_SYM && ctx.linecount < 1) {
				ctx.linecount++;
				ctx.linebegin = in + 1;
				continue;
			}
			if (ctx.type != TYPE_NONE && ctx.right && ctx.left && ctx.rightlen > 0 && ctx.leftlen > 0) {
				char* copy = NULL;
				if (ctx.leftlen > ctx.rightlen) {
					copy = (char*) malloc (ctx.leftlen);
					if (copy) {
						memcpy (copy, ctx.left, ctx.leftlen);
						memcpy (ctx.left, ctx.right, ctx.rightlen);
						memmove (ctx.comment - ctx.leftlen + ctx.rightlen, ctx.comment, ctx.right - ctx.comment);
						memcpy (ctx.right - ctx.leftlen + ctx.rightlen, copy, ctx.leftlen);
					}
				} else if (ctx.leftlen < ctx.rightlen) {
					if (ctx.linecount < 1) {
						copy = (char*) malloc (ctx.rightlen);
						if (copy) {
							memcpy (copy, ctx.right, ctx.rightlen);
							memcpy (ctx.right + ctx.rightlen - ctx.leftlen, ctx.left, ctx.leftlen);
							memmove (ctx.comment + ctx.rightlen - ctx.leftlen, ctx.comment, ctx.right - ctx.comment);
							memcpy (ctx.left + ctx.rightlen - ctx.leftlen, copy, ctx.rightlen);
						}
					} else {
//						copy = (char*) malloc (ctx.linebegin - ctx.left);
//						if (copy) {
//							memcpy (copy, ctx.left, ctx.linebegin - ctx.left);
						memset (ctx.right - ctx.leftpos, ' ', ctx.leftpos);
						*(ctx.right - ctx.leftpos - 1) = '\n';
//							memcpy (ctx.comment + 3, copy, ctx.linebegin - ctx.left);
						memset (ctx.left, ' ', ctx.leftlen);
						memset (ctx.linebegin - ctx.leftlen, ' ', ctx.leftlen);
//						}
					}
				} else if (ctx.leftlen == ctx.rightlen) {
					copy = (char*) malloc (ctx.leftlen);
					if (copy) {
						memcpy (copy, ctx.right, ctx.leftlen);
						memcpy (ctx.right, ctx.left, ctx.leftlen);
						memcpy (ctx.left, copy, ctx.leftlen);
					}
				}
				free (copy);
			}
			memset (&ctx, 0, sizeof (ctx));
			ctx.linebegin = in + 1;
		} else if (!ctx.comment && *in == ';' && in[1] == ' ') {
			ctx.comment = in - 1;
			ctx.comment[1] = '/';
			ctx.comment[2] = '/';
			while (!IS_WHITESPACE (*(ctx.comment - ctx.commentcolor))) {
				ctx.commentcolor++;
			}
			ctx.commentcolor--;
		} else if (!ctx.comment && ctx.type == TYPE_NONE) {
			if (IS_STRING (in, ctx)) {
				ctx.type = TYPE_STR;
				ctx.left = in;
				while (!IS_WHITESPACE (*(ctx.left - ctx.leftcolor))) {
					ctx.leftcolor++;
				}
				ctx.leftcolor--;
				ctx.leftpos = ctx.left - ctx.linebegin;
			} else if (IS_SYMBOL (in, ctx)) {
				ctx.type = TYPE_SYM;
				ctx.left = in;
				while (!IS_WHITESPACE (*(ctx.left - ctx.leftcolor))) {
					ctx.leftcolor++;
				}
				ctx.leftcolor--;
				ctx.leftpos = ctx.left - ctx.linebegin;
			}
		} else if (ctx.type == TYPE_STR) {
			if (!ctx.leftlen && ctx.left && IS_WHITESPACE (*in)) {
				ctx.leftlen = in - ctx.left;
			} else if (ctx.comment && *in == '"' && in[-1] != '\\') {
				if (!ctx.right) {
					ctx.right = in;
					while (!IS_WHITESPACE (*(ctx.right - ctx.rightcolor))) {
						ctx.rightcolor++;
					}
					ctx.rightcolor--;
				} else {
					ctx.rightlen = in - ctx.right + 1;
				}
			}
		} else if (ctx.type == TYPE_SYM) {
			if (!ctx.leftlen && ctx.left && IS_WHITESPACE (*in)) {
				ctx.leftlen = in - ctx.left + 3;
			} else if (ctx.comment && *in == '(' && IS_ALPHA (in[-1]) && !ctx.right) {
				// ok so i've found a function written in this way:
				// type = [const|void|int|float|double|short|long]
				// type fcn_name (type arg1, type arg2, ...)
				// right now 'in' points at '(', but the function name is before, so i'll go back
				// till a space is found
				// 'int print(const char*, ...)'
				//           ^
				ctx.right = in - 1;
				while (IS_ALPHA (*ctx.right) || *ctx.right == '_' || *ctx.right == '*') {
					ctx.right--;
				}
				// 'int print(const char*, ...)'
				//     ^
				// right now 'in' points at ' ' before 'p' , but there can be a return value
				// like 'int' in 'int print(const char*, ...)'.
				// so to find for example 'int' we have to go back till a space is found.
				// if a non alpha is found, then we can cut from the function name
				if (*ctx.right == ' ') {
					ctx.right--;
					while (IS_ALPHA (*ctx.right) || *ctx.right == '_' || *ctx.right == '*') {
						ctx.right--;
					}
					// moving forward since it points now to non alpha.
					ctx.right++;
				}
				while (!IS_WHITESPACE (*(ctx.right - ctx.rightcolor))) {
					ctx.rightcolor++;
				}
				ctx.rightcolor--;
			} else if (ctx.comment && *in == ')' && in[1] != '\'') {
				ctx.rightlen = in - ctx.right + 1;
			}
		}
	}
}

R_API int r_core_pseudo_code(RCore *core, const char *input) {
	Sdb *db;
	ut64 queuegoto = 0LL;
	const char *blocktype = "else";
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
	RConfigHold *hc = r_config_hold_new (core->config);
	if (!hc) {
		return false;
	}
	r_config_save_num (hc, "asm.pseudo", "asm.decode", "asm.lines", "asm.bytes", NULL);
	r_config_save_num (hc, "asm.offset", "asm.flags", "asm.fcnlines", "asm.comments", NULL);
	r_config_save_num (hc, "asm.functions", "asm.section", "asm.cmt.col", "asm.filter", NULL);
	r_config_save_num (hc, "scr.color", "asm.emu.str", "asm.emu", "asm.emu.write", NULL);
	r_config_save_num (hc, "io.cache", NULL);
	if (!fcn) {
		eprintf ("Cannot find function in 0x%08"PFMT64x"\n", core->offset);
		r_config_hold_free (hc);
		return false;
	}
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_i (core->config, "asm.pseudo", 1);
	r_config_set_i (core->config, "asm.decode", 0);
	r_config_set_i (core->config, "asm.filter", 1);
	r_config_set_i (core->config, "asm.lines", 0);
	r_config_set_i (core->config, "asm.bytes", 0);
	r_config_set_i (core->config, "asm.offset", 0);
	r_config_set_i (core->config, "asm.flags", 0);
	r_config_set_i (core->config, "asm.emu", 1);
	r_config_set_i (core->config, "asm.emu.str", 1);
	r_config_set_i (core->config, "asm.emu.write", 1);
	r_config_set_i (core->config, "asm.fcnlines", 0);
	r_config_set_i (core->config, "asm.comments", 1);
	r_config_set_i (core->config, "asm.functions", 0);
	r_config_set_i (core->config, "asm.tabs", 0);
	r_config_set_i (core->config, "asm.section", 0);
	r_config_set_i (core->config, "asm.cmt.col", 30);
	r_config_set_i (core->config, "io.cache", 1);
	r_core_cmd0 (core, "aeim");

	db = sdb_new0 ();
	// walk all basic blocks
	// define depth level for each block
	// use it for indentation
	// asm.pseudo=true
	// asm.decode=true
	RAnalBlock *bb = r_list_first (fcn->bbs);
	char indentstr[1024] = {0};
	int n_bb = r_list_length (fcn->bbs);
	r_cons_printf ("function %s () {", fcn->name);
	int indent = 1;
	int nindent = 1;
	RList *visited = r_list_newf (NULL);
	r_cons_printf ("\n    //  %d basic blocks\n", n_bb);
	do {
#define I_TAB 4
#define K_MARK(x) sdb_fmt(0,"mark.%"PFMT64x,x)
#define K_ELSE(x) sdb_fmt(0,"else.%"PFMT64x,x)
#define K_INDENT(x) sdb_fmt(0,"loc.%"PFMT64x,x)
#define SET_INDENT(x) { x = x>0?x:1; memset (indentstr, ' ', x*I_TAB); indentstr [(x*I_TAB)-2] = 0; }
		if (!bb) {
			break;
		}
		r_list_append (visited, bb);
		r_cons_push ();
		bool html = r_config_get_i (core->config, "scr.html");
		r_config_set_i (core->config, "scr.html", 0);
		char *code = r_core_cmd_str (core, sdb_fmt (0, "pD %d @ 0x%08"PFMT64x"\n", bb->size, bb->addr));
		r_cons_pop ();
		r_config_set_i (core->config, "scr.html", html);
		if (indent * I_TAB + 2 >= sizeof (indentstr)) {
			indent = (sizeof (indentstr) / I_TAB) - 4;
		}
		SET_INDENT (indent);
		code = r_str_prefix_all (code, indentstr);
		if (!code) {
			eprintf ("No code here\n");
			break;
		}
		int len = strlen (code);
		code[len - 1] = 0; // chop last newline
		find_and_change (code, len);
		if (!sdb_const_get (db, K_MARK (bb->addr), 0)) {
			bool mustprint = !queuegoto || queuegoto != bb->addr;
			if (mustprint) {
				if (queuegoto) {
					r_cons_printf ("\n%s  goto loc_0x%llx",
						indentstr, queuegoto);
					queuegoto = 0LL;
				}
				r_cons_printf ("\n%s  loc_0x%llx:\n", indentstr, bb->addr);
				indentstr[(indent * I_TAB) - 2] = 0;
				r_cons_printf ("\n%s", code);
				free (code);
				sdb_num_set (db, K_MARK (bb->addr), 1, 0);
			}
		}
		if (sdb_const_get (db, K_INDENT (bb->addr), 0)) {
			// already analyzed, go pop and continue
			// XXX check if cant pop
			//eprintf ("%s// 0x%08llx already analyzed\n", indentstr, bb->addr);
			ut64 addr = sdb_array_pop_num (db, "indent", NULL);
			if (addr == UT64_MAX) {
				int i;
				nindent = 1;
				for (i = indent; i != nindent; i--) {
					SET_INDENT (i);
					r_cons_printf ("\n%s}", indentstr);
				}
				r_cons_printf ("\n%sreturn;\n", indentstr);
				RAnalBlock *nbb = r_anal_bb_from_offset (core->anal, bb->fail);
				if (r_list_contains (visited, nbb)) {
					nbb = r_anal_bb_from_offset (core->anal, bb->jump);
					if (r_list_contains (visited, nbb)) {
						nbb = NULL;
					}
				}
				if (!nbb) {
					break;
				}
				bb = nbb;
				indent--;
				continue;
			}
			if (sdb_num_get (db, K_ELSE (bb->addr), 0)) {
				if (!strcmp (blocktype, "else")) {
					r_cons_printf ("\n%s } %s {", indentstr, blocktype);
				} else {
					r_cons_printf ("\n%s } %s (?);", indentstr, blocktype);
				}
			} else {
				r_cons_printf ("\n%s}", indentstr);
			}
			if (addr != bb->addr) {
				queuegoto = addr;
				// r_cons_printf ("\n%s  goto loc_0x%llx", indentstr, addr);
			}
			bb = r_anal_bb_from_offset (core->anal, addr);
			if (!bb) {
				eprintf ("failed block\n");
				break;
			}
			//eprintf ("next is %llx\n", addr);
			nindent = sdb_num_get (db, K_INDENT (addr), NULL);
			if (indent > nindent && !strcmp (blocktype, "else")) {
				int i;
				for (i = indent; i != nindent; i--) {
					SET_INDENT (i);
					r_cons_printf ("\n%s }", indentstr);
				}
			}
			indent = nindent;
		} else {
			sdb_set (db, K_INDENT (bb->addr), "passed", 0);
			if (bb->jump != UT64_MAX) {
				int swap = 1;
				// TODO: determine which branch take first
				ut64 jump = swap ? bb->jump : bb->fail;
				ut64 fail = swap ? bb->fail : bb->jump;
				// if its from another function chop it!
				RAnalFunction *curfcn = r_anal_get_fcn_in (core->anal, jump, R_ANAL_FCN_TYPE_NULL);
				if (curfcn != fcn) {
					// chop that branch
					r_cons_printf ("\n  // chop\n");
				//	break;
				}
				if (sdb_get (db, K_INDENT (jump), 0)) {
					// already tracekd
					if (!sdb_get (db, K_INDENT (fail), 0)) {
						bb = r_anal_bb_from_offset (core->anal, fail);
					}
				} else {
					bb = r_anal_bb_from_offset (core->anal, jump);
					if (!bb) {
						eprintf ("failed to retrieve blcok at 0x%"PFMT64x"\n", jump);
						break;
					}
					if (fail != UT64_MAX) {
						// do not push if already pushed
						indent++;
						if (sdb_get (db, K_INDENT (bb->fail), 0)) {
							/* do nothing here */
							eprintf ("BlockAlready 0x%"PFMT64x"\n", bb->addr);
						} else {
							//		r_cons_printf (" { RADICAL %llx\n", bb->addr);
							sdb_array_push_num (db, "indent", fail, 0);
							sdb_num_set (db, K_INDENT (fail), indent, 0);
							sdb_num_set (db, K_ELSE (fail), 1, 0);
							SET_INDENT (indent);
							r_cons_printf ("\n%s {", indentstr);
						}
					} else {
						r_cons_printf ("\n%s do", indentstr);
						sdb_array_push_num (db, "indent", jump, 0);
						sdb_num_set (db, K_INDENT (jump), indent, 0);
						sdb_num_set (db, K_ELSE (jump), 1, 0);
						if (jump <= bb->addr) {
							blocktype = "while";
						} else {
							blocktype = "else";
						}
						r_cons_printf ("\n%s {", indentstr);
						indent++;
					}
				}
			} else {
				ut64 addr = sdb_array_pop_num (db, "indent", NULL);
				if (addr == UT64_MAX) {
					r_cons_printf ("\n(break)\n");
					break;
				}
				bb = r_anal_bb_from_offset (core->anal, addr);
				nindent = sdb_num_get (db, K_INDENT (addr), NULL);
				if (indent > nindent) {
					int i;
					for (i = indent; i != nindent; i--) {
						SET_INDENT (i);
						r_cons_printf ("\n%s}", indentstr);
					}
				}
				if (nindent != indent) {
					r_cons_printf ("\n%s} else {\n", indentstr);
				}
				indent = nindent;
			}
		}
		//n_bb --;
	} while (n_bb > 0);
	r_list_free (visited);
	r_cons_printf ("\n}\n");
	r_config_restore (hc);
	r_config_hold_free (hc);
	sdb_free (db);
	return true;
}
