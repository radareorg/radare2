/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_list.h>
#include <r_flags.h>
#include <r_core.h>

static char *r_core_anal_graph_label(RCore *core, struct r_anal_bb_t *bb, int opts) {
	struct r_anal_aop_t *aopi;
	RListIter *iter;
	char cmd[1024], file[1024], *cmdstr = NULL, *filestr = NULL, *str = NULL;
	int i, j, line = 0, oline = 0, idx = 0;

	if (opts == R_CORE_ANAL_GRAPHLINES) {
		r_list_foreach (bb->aops, iter, aopi) {
			r_bin_meta_get_line (core->bin, aopi->addr, file, 1023, &line);
			if (line != 0 && line != oline && strcmp (file, "??")) {
				filestr = r_file_slurp_line (file, line, 0);
				if (filestr) {
					cmdstr = realloc (cmdstr, idx + strlen (filestr) + 3);
					cmdstr[idx] = 0;
					strcat (cmdstr, filestr);
					strcat (cmdstr, "\\l");
					idx+=strlen (filestr);
					free (filestr);
				}
			}
			oline = line;
		}
	} else if (opts == R_CORE_ANAL_GRAPHBODY) {
		snprintf (cmd, sizeof (cmd), "pD %"PFMT64d" @ 0x%08"PFMT64x"", bb->size, bb->addr);
		cmdstr = r_core_cmd_str (core, cmd);
	}
	if (cmdstr) {
		if (!(str = malloc(strlen(cmdstr)*2)))
			return NULL;
		for(i=j=0;cmdstr[i];i++,j++) {
			switch(cmdstr[i]) {
				case 0x1b:
					/* skip ansi chars */
					for(i++;cmdstr[i]&&cmdstr[i]!='m'&&cmdstr[i]!='H'&&cmdstr[i]!='J';i++);
					j--;
					break;
				case '"':
					str[j]='\\';
					str[++j]='"';
					break;
				case '\n':
				case '\r':
					str[j]='\\';
					str[++j]='l';
					break;
				default:
					str[j]=cmdstr[i];
			}
		}
		str[j]='\0';
		free (cmdstr);
	}
	return str;
}

static void r_core_anal_graph_nodes(RCore *core, RList *pbb, ut64 addr, int opts) {
	struct r_anal_bb_t *bbi, *bbc;
	RListIter *iter;
	char *str;

	if (pbb) { 
		/* In partial graphs test if the bb is already printed */
		r_list_foreach (pbb, iter, bbi) {
			if (addr >= bbi->addr && addr < bbi->addr+bbi->size)
				return;
		}
	}

	r_list_foreach (core->anal->bbs, iter, bbi) {
		if (addr == 0 || (addr >= bbi->addr && addr < bbi->addr+bbi->size)) {
			if (pbb) { /* Copy BB and append to the list of printed bbs */
				bbc = R_NEW (RAnalBlock);
				memcpy (bbc, bbi, sizeof (RAnalBlock));
				r_list_append (pbb, bbc);
			}
			if (bbi->jump != -1) {
				r_cons_printf ("\t\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" [color=\"%s\"];\n", bbi->addr, bbi->jump,
						bbi->fail != -1 ? "green" : "blue");
				r_cons_flush ();
				if (addr != 0) r_core_anal_graph_nodes (core, pbb, bbi->jump, opts);
			}
			if (bbi->fail != -1) {
				r_cons_printf ("\t\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" [color=\"red\"];\n", bbi->addr, bbi->fail);
				r_cons_flush ();
				if (addr != 0) r_core_anal_graph_nodes (core, pbb, bbi->fail, opts);
			}
			if ((str = r_core_anal_graph_label (core, bbi, opts))) {
				r_cons_printf (" \"0x%08"PFMT64x"\" [label=\"%s\"]\n", bbi->addr, str);
				r_cons_flush ();
				free (str);
			}
		}
	}
}

R_API int r_core_anal_bb(RCore *core, ut64 at, int depth, int head) {
	struct r_anal_bb_t *bb;
	ut64 jump, fail;
	ut8 *buf;
	int ret, buflen, bblen = 0;

	if (depth < 0)
		return R_FALSE;
	if (!(bb = r_anal_bb_new()))
		return R_FALSE;
	ret = r_anal_bb_split (core->anal, bb, core->anal->bbs, at);
	if (ret == R_ANAL_RET_DUP) { /* Dupped bb */
		r_anal_bb_free (bb);
		return R_FALSE;
	} else if (ret == R_ANAL_RET_NEW) { /* New bb */
		if (!(buf = malloc (core->blocksize)))
			return R_FALSE;
		do {
			if ((buflen = r_io_read_at (core->io, at+bblen, buf, core->blocksize)) != core->blocksize)
				return R_FALSE;
			bblen = r_anal_bb (core->anal, bb, at+bblen, buf, buflen, head); 
			if (bblen == R_ANAL_RET_ERROR) { /* Error analyzing bb */
				r_anal_bb_free (bb);
				return R_FALSE;
			} else if (bblen == R_ANAL_RET_END) { /* bb analysis complete */
				if (r_anal_bb_overlap (core->anal, bb, core->anal->bbs) == R_ANAL_RET_NEW) {
					r_list_append (core->anal->bbs, bb);
					fail = bb->fail;
					jump = bb->jump;
					if (fail != -1)
						r_core_anal_bb (core, fail, depth-1, R_FALSE);
					if (jump != -1)
						r_core_anal_bb (core, jump, depth-1, R_FALSE);
				}
			}
		} while (bblen != R_ANAL_RET_END);
		free (buf);
	}
	return R_TRUE;
}

R_API int r_core_anal_bb_list(RCore *core, int rad) {
	struct r_anal_bb_t *bbi;
	RListIter *iter;

	r_list_foreach (core->anal->bbs, iter, bbi) {
		if (rad) {
			r_cons_printf ("ab+ 0x%08"PFMT64x" %04"PFMT64d" ", bbi->addr, bbi->size);
			if (bbi->jump != -1)
				r_cons_printf ("%08"PFMT64x" ", bbi->jump);
			if (bbi->jump != -1 && bbi->fail != -1)
				r_cons_printf ("%08"PFMT64x" ", bbi->fail);
			if ((bbi->type & R_ANAL_BB_TYPE_BODY))
				r_cons_printf ("b");
			if ((bbi->type & R_ANAL_BB_TYPE_FOOT))
				r_cons_printf ("f");
			if ((bbi->type & R_ANAL_BB_TYPE_HEAD))
				r_cons_printf ("h");
			if ((bbi->type & R_ANAL_BB_TYPE_LAST))
				r_cons_printf ("l");
			r_cons_printf ("\n");
		} else {
			r_cons_printf ("[0x%08"PFMT64x"] size=%04"PFMT64d" ", bbi->addr, bbi->size);
			if (bbi->jump != -1)
				r_cons_printf ("jump=%08"PFMT64x" ", bbi->jump);
			if (bbi->fail != -1)
				r_cons_printf ("fail=%08"PFMT64x" ", bbi->fail);
			r_cons_printf ("type = ");
			if (bbi->type == R_ANAL_BB_TYPE_NULL)
				r_cons_printf ("null");
			else {
			if ((bbi->type & R_ANAL_BB_TYPE_BODY))
				r_cons_printf ("body ");
			if ((bbi->type & R_ANAL_BB_TYPE_FOOT))
				r_cons_printf ("foot ");
			if ((bbi->type & R_ANAL_BB_TYPE_HEAD))
				r_cons_printf ("head ");
			if ((bbi->type & R_ANAL_BB_TYPE_LAST))
				r_cons_printf ("last ");
			}
			r_cons_printf ("\n");
		}
	}
	r_cons_flush ();
	return R_TRUE;
}

R_API int r_core_anal_bb_seek(RCore *core, ut64 addr) {
	struct r_anal_bb_t *bbi;
	RListIter *iter;

	r_list_foreach (core->anal->bbs, iter, bbi)
		if (addr >= bbi->addr && addr < bbi->addr+bbi->size)
			return r_core_seek (core, bbi->addr, R_FALSE);
	return r_core_seek (core, addr, R_FALSE);
}

R_API int r_core_anal_fcn(RCore *core, ut64 at, ut64 from, int depth) {
	RAnalFcn *fcn, *fcni;
	struct r_anal_ref_t *refi;
	RListIter *iter, *iter2;
	char *flagname;
	ut64 *ref;
	ut8 *buf;
	int buflen, fcnlen = 0;

	if (depth < 0)
		return R_FALSE;
	r_list_foreach (core->anal->fcns, iter, fcni)
		if ((at >= fcni->addr && at < fcni->addr+fcni->size) ||
			(at == fcni->addr && fcni->size == 0)) {
			if (from != -1) {
				r_list_foreach (fcni->xrefs, iter2, refi) {
					ref = (ut64*)refi;
					if (from == *ref)
						return R_FALSE;
				}
				if (!(ref = r_anal_ref_new())) {
					eprintf ("Error: new (xref)\n");
					return R_ANAL_RET_ERROR;
				}
				*ref = from;
				r_list_append (fcni->xrefs, ref);
			}
			return R_FALSE;
		}
	if (!(fcn = r_anal_fcn_new()))
		return R_FALSE;
	if (!(buf = malloc (core->blocksize)))
		return R_FALSE;
	do {
		if ((buflen = r_io_read_at (core->io, at+fcnlen, buf, core->blocksize)) != core->blocksize)
			return R_FALSE;
		fcnlen = r_anal_fcn (core->anal, fcn, at+fcnlen, buf, buflen); 
		if (fcnlen == R_ANAL_RET_ERROR) { /* Error analyzing function */
			eprintf ("Unknown opcode at 0x%08"PFMT64x"\n", at+fcnlen);
			r_anal_fcn_free (fcn);
			return R_FALSE;
		} else if (fcnlen == R_ANAL_RET_END) { /* function analysis complete */
			fcn->name = r_str_dup_printf ("fcn_%08"PFMT64x"", at);
			/* Add flag */
			flagname = r_str_dup_printf ("fcn.%s", fcn->name);
			r_flag_space_set (core->flags, "functions");
			r_flag_set (core->flags, flagname, at, fcn->size, 0);
			free (flagname);
			r_list_append (core->anal->fcns, fcn);
			r_list_foreach (fcn->refs, iter, refi) {
				ref = (ut64*)refi;
				if (*ref != -1)
					r_core_anal_fcn (core, *ref, at, depth-1);
			}
		}
	} while (fcnlen != R_ANAL_RET_END);
	free (buf);
	return R_TRUE;
}

R_API int r_core_anal_fcn_clean(RCore *core, ut64 addr) {
	RAnalFcn *fcni;
	RListIter *iter;

	if (addr == 0) {
		r_list_destroy (core->anal->fcns);
		if (!(core->anal->fcns = r_anal_fcn_list_new ()))
			return R_FALSE;
	} else r_list_foreach (core->anal->fcns, iter, fcni)
			if (addr >= fcni->addr && addr < fcni->addr+fcni->size)
				r_list_unlink (core->anal->fcns, fcni);
	return R_TRUE;
}

R_API void r_core_anal_refs(RCore *core, ut64 addr, int gv) {
	ut64 *ref;
	RAnalRef *fcnr;
	RAnalFcn *fcni;
	RListIter *iter, *iter2;

	if (gv)
	r_cons_printf ("digraph code {\n"
		"\tgraph [bgcolor=white];\n"
		"\tnode [color=lightgray, style=filled shape=box"
		" fontname=\"Courier\" fontsize=\"8\"];\n");

	r_list_foreach (core->anal->fcns, iter, fcni) {
		if (addr != 0 && addr != fcni->addr)
			continue;
		if (!gv)
			r_cons_printf ("0x%08"PFMT64x"\n", fcni->addr);
		r_list_foreach (fcni->refs, iter2, fcnr) {
			char *name = "";
			RFlagItem *flag;
			ref = (ut64*)fcnr;
			flag = r_flag_get_i (core->flags, *ref);
			if (flag)
				name = flag->name;
			if (gv) r_cons_printf ("\t\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" [label=\"%s\" color=\"%s\"];\n",
				fcni->addr, *ref, name, "green");
			else r_cons_printf (" - 0x%08"PFMT64x"\n", *ref);
		}
	}
	r_cons_printf ("}\n");
}

R_API int r_core_anal_fcn_add(RCore *core, ut64 addr, ut64 size, const char *name) {
	RAnalFcn *fcn, *fcni;
	RListIter *iter;

	r_list_foreach (core->anal->fcns, iter, fcni)
		if (addr >= fcni->addr && addr < fcni->addr+fcni->size)
			return R_FALSE;
	if (!(fcn = r_anal_fcn_new ()))
		return R_FALSE;
	fcn->addr = addr;
	fcn->size = size;
	fcn->name = strdup (name);
	r_list_append (core->anal->fcns, fcn);
	return R_TRUE;
}

R_API int r_core_anal_fcn_list(RCore *core, int rad) {
	RAnalFcn *fcni;
	struct r_anal_ref_t *refi;
	struct r_anal_var_t *vari;
	RListIter *iter, *iter2;
	ut64 *ref;

	r_list_foreach (core->anal->fcns, iter, fcni)
		if (rad) r_cons_printf ("af+ 0x%08"PFMT64x" %"PFMT64d" %s\n", fcni->addr, fcni->size, fcni->name);
		else {
			r_cons_printf ("[0x%08"PFMT64x"] size=%"PFMT64d" name=%s",
					fcni->addr, fcni->size, fcni->name);
			r_cons_printf ("\n  refs: ");
			r_list_foreach (fcni->refs, iter2, refi) {
				ref = (ut64*)refi;
				r_cons_printf ("0x%08"PFMT64x" ", *ref);
			}
			r_cons_printf ("\n  xrefs: ");
			r_list_foreach (fcni->xrefs, iter2, refi) {
				ref = (ut64*)refi;
				r_cons_printf ("0x%08"PFMT64x" ", *ref);
			}
			r_cons_printf ("\n  vars:\n");
			r_list_foreach (fcni->vars, iter2, vari) {
				r_cons_printf ("  %-10s delta=0x%02x type=%s\n", vari->name, vari->delta,
					r_anal_var_type_to_str (core->anal, vari->type));
			}
			r_cons_newline ();
		}
	r_cons_flush ();
	return R_TRUE;
}

R_API int r_core_anal_graph(RCore *core, ut64 addr, int opts) {
	RList *pbb = NULL;
	int reflines = r_config_get_i (core->config, "asm.lines");
	int bytes = r_config_get_i (core->config, "asm.bytes");
	int dwarf = r_config_get_i (core->config, "asm.dwarf");

	r_config_set_i (core->config, "asm.lines", 0);
	r_config_set_i (core->config, "asm.bytes", 0);
	r_config_set_i (core->config, "asm.dwarf", 0);
	r_cons_printf ("digraph code {\n"
		"\tgraph [bgcolor=white];\n"
		"\tnode [color=lightgray, style=filled shape=box"
		" fontname=\"Courier\" fontsize=\"8\"];\n");
	r_cons_flush ();
	if (addr != 0) pbb = r_anal_bb_list_new (); /* In partial graphs define printed bb list */
	r_core_anal_graph_nodes (core, pbb, addr, opts);
	if (pbb) r_list_destroy (pbb);
	r_cons_printf ("}\n");
	r_cons_flush ();
	r_config_set_i (core->config, "asm.lines", reflines);
	r_config_set_i (core->config, "asm.bytes", bytes);
	r_config_set_i (core->config, "asm.dwarf", dwarf);
	return R_TRUE;
}

R_API int r_core_anal_graph_fcn(RCore *core, char *fname, int opts) {
	RListIter *iter;
	RAnalFcn *fcni;

	r_list_foreach (core->anal->fcns, iter, fcni)
		if (!strcmp (fname, fcni->name))
			return r_core_anal_graph (core, fcni->addr, opts);
	return R_FALSE;
}
