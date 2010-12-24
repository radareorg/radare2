/* radare - LGPL - Copyright 2009-2010 */
/* pancake<nopcode.org> */
/* nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_list.h>
#include <r_flags.h>
#include <r_core.h>

static char *r_core_anal_graph_label(RCore *core, struct r_anal_bb_t *bb, int opts) {
	RAnalOp *aopi;
	RListIter *iter;
	char cmd[1024], file[1024], *cmdstr = NULL, *filestr = NULL, *str = NULL;
	int i, j, line = 0, oline = 0, idx = 0;

	if (opts & R_CORE_ANAL_GRAPHLINES) {
		r_list_foreach (bb->aops, iter, aopi) {
			r_bin_meta_get_line (core->bin, aopi->addr, file, sizeof (file)-1, &line);
			if (line != 0 && line != oline && strcmp (file, "??")) {
				filestr = r_file_slurp_line (file, line, 0);
				if (filestr) {
					cmdstr = realloc (cmdstr, idx + strlen (filestr) + 3);
					cmdstr[idx] = 0;
					// TODO: optimize all this strcat stuff
					strcat (cmdstr, filestr);
					strcat (cmdstr, "\\l");
					idx += strlen (filestr);
					free (filestr);
				}
			}
			oline = line;
		}
	} else if (opts & R_CORE_ANAL_GRAPHBODY) {
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

	/* In partial graphs test if the bb is already printed */
	if (pbb)
		r_list_foreach (pbb, iter, bbi)
			if (addr == bbi->addr)
				return;

	r_list_foreach (core->anal->bbs, iter, bbi) {
		if (addr == 0 || addr == bbi->addr) {
			if (pbb) { /* Copy BB and append to the list of printed bbs */
				bbc = R_NEW (RAnalBlock);
				if (bbc) {
					memcpy (bbc, bbi, sizeof (RAnalBlock));
					/* We don't want to free this refs when the temporary list is destroyed */
					bbc->aops = NULL;
					bbc->cond = NULL;
					bbc->diff = NULL;
					bbc->fingerprint = NULL;
					r_list_append (pbb, bbc);
				}
			}
			if (bbi->jump != -1) {
				r_cons_printf ("\t\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
						"[color=\"%s\"];\n", bbi->addr, bbi->jump,
						bbi->fail != -1 ? "green" : "blue");
				r_cons_flush ();
				if (addr != 0) r_core_anal_graph_nodes (core, pbb, bbi->jump, opts);
			}
			if (bbi->fail != -1) {
				r_cons_printf ("\t\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
					"[color=\"red\"];\n", bbi->addr, bbi->fail);
				r_cons_flush ();
				if (addr != 0) r_core_anal_graph_nodes (core, pbb, bbi->fail, opts);
			}
			if ((str = r_core_anal_graph_label (core, bbi, opts))) {
				if (opts & R_CORE_ANAL_GRAPHDIFF) {
					r_cons_printf (" \"0x%08"PFMT64x"\" [color=\"%s\", label=\"%s\"]\n", bbi->addr, 
						bbi->diff->type==R_ANAL_DIFF_TYPE_MATCH?"lightgray":
						bbi->diff->type==R_ANAL_DIFF_TYPE_UNMATCH?"yellow":"red",str);
				} else {
					r_cons_printf (" \"0x%08"PFMT64x"\" [color=\"%s\", label=\"%s\"]\n", bbi->addr,
						bbi->traced?"yellow":"lightgray",str);
				}
				r_cons_flush ();
				free (str);
			}
		}
	}
}

static int fcn_cc(RCore *core, RList *pbb, ut64 addr) {
	struct r_anal_bb_t *bbi, *bbc;
	RListIter *iter;
	int ret = -1, jcalls = 0, fcalls = 0;

	if (!pbb)
		return -1;

	/* Test if the bb has been analyzed before */
	r_list_foreach (pbb, iter, bbi)
		if (addr == bbi->addr)
			return 0;

	r_list_foreach (core->anal->bbs, iter, bbi)
		if (addr == bbi->addr) {
			/* Copy BB and append to the list of printed bbs */
			bbc = R_NEW (RAnalBlock);
			if (!bbc)
				return -1;
			memcpy (bbc, bbi, sizeof (RAnalBlock));
			/* We don't want to free this refs when the temporary list is destroyed */
			bbc->aops = NULL;
			bbc->cond = NULL;
			bbc->diff = NULL;
			bbc->fingerprint = NULL;
			r_list_append (pbb, bbc);
			if (bbi->jump != -1) {
				jcalls = fcn_cc (core, pbb, bbi->jump);
				if (jcalls == -1)
					return -1;
			}
			if (bbi->fail != -1) {
				fcalls = fcn_cc (core, pbb, bbi->fail);
				if (fcalls == -1)
					return -1;
			}
			ret = bbi->conditional + bbi->ncalls + jcalls + fcalls;
			break;
		}
	return ret;
}

R_API int r_core_anal_bb(RCore *core, RList *bbs, ut64 at, int depth, int head) {
	struct r_anal_bb_t *bb, *bbi;
	RListIter *iter;
	ut64 jump, fail;
	ut8 *buf;
	int ret = R_ANAL_RET_NEW, buflen, bblen = 0;
	int split = core->anal->split;

	if (depth < 0)
		return R_FALSE;
	if (!(bb = r_anal_bb_new()))
		return R_FALSE;
	if (split) ret = r_anal_bb_split (core->anal, bb, bbs, at);
	else r_list_foreach (bbs, iter, bbi)
		if (at == bbi->addr)
			ret = R_ANAL_RET_DUP;
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
				if (split)
					ret = r_anal_bb_overlap (core->anal, bb, bbs);
				if (ret == R_ANAL_RET_NEW) {
					r_list_append (bbs, bb);
					fail = bb->fail;
					jump = bb->jump;
					if (fail != -1)
						r_core_anal_bb (core, bbs, fail, depth-1, R_FALSE);
					if (jump != -1)
						r_core_anal_bb (core, bbs, jump, depth-1, R_FALSE);
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
			r_cons_printf ("0x%08"PFMT64x" ", bbi->jump);
			r_cons_printf ("0x%08"PFMT64x" ", bbi->fail);

			if (bbi->type != R_ANAL_BB_TYPE_NULL) {
				if ((bbi->type & R_ANAL_BB_TYPE_BODY))
					r_cons_printf ("b");
				if ((bbi->type & R_ANAL_BB_TYPE_FOOT))
					r_cons_printf ("f");
				if ((bbi->type & R_ANAL_BB_TYPE_HEAD))
					r_cons_printf ("h");
				if ((bbi->type & R_ANAL_BB_TYPE_LAST))
					r_cons_printf ("l");
			} else r_cons_printf ("n");

			if ((bbi->diff->type == R_ANAL_DIFF_TYPE_MATCH))
				r_cons_printf (" m");
			else if ((bbi->diff->type == R_ANAL_DIFF_TYPE_UNMATCH))
				r_cons_printf (" u");
			else r_cons_printf (" n");
			r_cons_printf ("\n");
		} else {
			r_cons_printf ("[0x%08"PFMT64x"] size=%04"PFMT64d, bbi->addr, bbi->size);
			if (bbi->jump != -1)
				r_cons_printf (" jump=0x%08"PFMT64x, bbi->jump);
			if (bbi->fail != -1)
				r_cons_printf (" fail=0x%08"PFMT64x, bbi->fail);

			r_cons_printf (" type=");
			if (bbi->type != R_ANAL_BB_TYPE_NULL) {
				if ((bbi->type & R_ANAL_BB_TYPE_BODY))
					r_cons_printf ("body,");
				if ((bbi->type & R_ANAL_BB_TYPE_FOOT))
					r_cons_printf ("foot,");
				if ((bbi->type & R_ANAL_BB_TYPE_HEAD))
					r_cons_printf ("head,");
				if ((bbi->type & R_ANAL_BB_TYPE_LAST))
					r_cons_printf ("last ");
			} else r_cons_printf ("null ");

			r_cons_printf ("diff=");
			if ((bbi->diff->type == R_ANAL_DIFF_TYPE_MATCH))
				r_cons_printf ("match");
			else if ((bbi->diff->type == R_ANAL_DIFF_TYPE_UNMATCH))
				r_cons_printf ("unmatch");
			else r_cons_printf ("new");

			r_cons_printf (" traced=%d", bbi->traced);
			if (bbi->cond)
				r_cons_printf (" cond=\"%s\" match=%d\n",
					r_anal_cond_to_string (bbi->cond),
					r_anal_cond_eval (core->anal, bbi->cond));
			else r_cons_newline ();
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

R_API int r_core_anal_fcn(RCore *core, ut64 at, ut64 from, int reftype, int depth) {
	RAnalFcn *fcn, *fcni;
	struct r_anal_ref_t *refi;
	RListIter *iter, *iter2;
	RAnalRef *ref;
	ut8 *buf;
	int buflen, fcnlen = 0;

	if (depth < 0)
		return R_FALSE;
	r_list_foreach (core->anal->fcns, iter, fcni)
		if (at == fcni->addr) { /* Function already analyzed */
			if (from != -1) {
				r_list_foreach (fcni->xrefs, iter2, refi) /* If the xref is new, add it */
					if (from == refi->addr)
						return R_TRUE;
				if (!(ref = r_anal_ref_new ())) {
					eprintf ("Error: new (xref)\n");
					return R_FALSE;
				}
				ref->addr = from;
				ref->at = at;
				ref->type = reftype;
				r_list_append (fcni->xrefs, ref);
			}
			return R_TRUE;
		}
	if (!(fcn = r_anal_fcn_new())) {
		eprintf ("Error: new (fcn)\n");
		return R_FALSE;
	}
	if (!(buf = malloc (core->blocksize))) {
		eprintf ("Error: malloc (buf)\n");
		return R_FALSE;
	}

	do {
		if ((buflen = r_io_read_at (core->io, at+fcnlen, buf, core->blocksize)) != core->blocksize)
			return R_FALSE;
		fcnlen = r_anal_fcn (core->anal, fcn, at+fcnlen, buf, buflen, reftype); 
		if (fcnlen == R_ANAL_RET_ERROR) { /* Error analyzing function */
			r_anal_fcn_free (fcn);
			return R_FALSE;
		} else if (fcnlen == R_ANAL_RET_END) { /* Function analysis complete */
			RFlagItem *f = r_flag_get_i (core->flags, at);
			if (f) { /* Check if it's already flagged */
				fcn->name = strdup (f->name);
			} else {
				fcn->name = r_str_dup_printf ("%s.%08"PFMT64x,
						fcn->type == R_ANAL_FCN_TYPE_LOC?"loc":"fcn", at);
				/* Add flag */
				r_flag_space_set (core->flags, "functions");
				r_flag_set (core->flags, fcn->name, at, fcn->size, 0);
			}
			/* TODO: Dupped analysis, needs more optimization */
			r_core_anal_bb (core, fcn->bbs, fcn->addr, depth, R_TRUE);
			/* New function: Add initial xref */
			if (from != -1) {
				if (!(ref = r_anal_ref_new ())) {
					eprintf ("Error: new (xref)\n");
					return R_FALSE;
				}
				ref->addr = from;
				ref->at = at;
				ref->type = reftype;
				r_list_append (fcn->xrefs, ref);
			}
			r_list_append (core->anal->fcns, fcn);
			r_list_foreach (fcn->refs, iter, refi)
				if (refi->addr != -1)
					r_core_anal_fcn (core, refi->addr, refi->at, refi->type, depth-1);
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
	RListIter *iter, *iter2;
	RAnalRef *fcnr;
	RAnalFcn *fcni;

	if (gv) r_cons_printf ("digraph code {\n"
		"\tgraph [bgcolor=white];\n"
		"\tnode [color=lightgray, style=filled shape=box"
		" fontname=\"Courier\" fontsize=\"8\"];\n");
	r_list_foreach (core->anal->fcns, iter, fcni) {
		if (addr != 0 && addr != fcni->addr)
			continue;
		if (!gv) r_cons_printf ("0x%08"PFMT64x"\n", fcni->addr);
		r_list_foreach (fcni->refs, iter2, fcnr) {
			// TODO: display only code or data refs?
			RFlagItem *flag = r_flag_get_i (core->flags, fcnr->addr);
			if (gv) r_cons_printf ("\t\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
					"[label=\"%s\" color=\"%s\"];\n",
				fcni->addr, fcnr->addr, flag?flag->name:"",
				(fcnr->type==R_ANAL_REF_TYPE_CODE ||
				 fcnr->type==R_ANAL_REF_TYPE_CALL)?"green":"red");
			else r_cons_printf (" - 0x%08"PFMT64x" (%c)\n", fcnr->addr, fcnr->type);
		}
	}
	r_cons_printf ("}\n");
}

R_API int r_core_anal_fcn_list(RCore *core, const char *input, int rad) {
	RAnalFcn *fcni;
	struct r_anal_ref_t *refi;
	struct r_anal_var_t *vari;
	RListIter *iter, *iter2;

	r_list_foreach (core->anal->fcns, iter, fcni)
		if (input == NULL || input[0] == '\0' || !strcmp (fcni->name, input+1)) {
			if (!rad) {
				r_cons_printf ("[0x%08"PFMT64x"] size=%"PFMT64d" name=%s",
						fcni->addr, fcni->size, fcni->name);
				r_cons_printf (" type=%s",
						fcni->type==R_ANAL_FCN_TYPE_LOC?"loc":"fcn");
				if (fcni->type==R_ANAL_FCN_TYPE_FCN)
					r_cons_printf (" [%s]",
							fcni->diff->type==R_ANAL_DIFF_TYPE_MATCH?"MATCH":
							fcni->diff->type==R_ANAL_DIFF_TYPE_UNMATCH?"UNMATCH":"NEW");

				r_cons_printf ("\n  CODE refs: ");
				r_list_foreach (fcni->refs, iter2, refi)
					if (refi->type == R_ANAL_REF_TYPE_CODE ||
						refi->type == R_ANAL_REF_TYPE_CALL)
						r_cons_printf ("0x%08"PFMT64x"(%c) ", refi->addr,
								refi->type==R_ANAL_REF_TYPE_CALL?'C':'J');

				r_cons_printf ("\n  DATA refs: ");
				r_list_foreach (fcni->refs, iter2, refi)
					if (refi->type == R_ANAL_REF_TYPE_DATA)
						r_cons_printf ("0x%08"PFMT64x" ", refi->addr);

				r_cons_printf ("\n  CODE xrefs: ");
				r_list_foreach (fcni->xrefs, iter2, refi)
					if (refi->type == R_ANAL_REF_TYPE_CODE ||
						refi->type == R_ANAL_REF_TYPE_CALL)
						r_cons_printf ("0x%08"PFMT64x"(%c) ", refi->addr,
								refi->type==R_ANAL_REF_TYPE_CALL?'C':'J');

				r_cons_printf ("\n  DATA xrefs: ");
				r_list_foreach (fcni->xrefs, iter2, refi)
					if (refi->type == R_ANAL_REF_TYPE_DATA)
						r_cons_printf ("0x%08"PFMT64x" ", refi->addr);

				if (fcni->type==R_ANAL_FCN_TYPE_FCN) {
					r_cons_printf ("\n  vars:");
					r_list_foreach (fcni->vars, iter2, vari)
						r_cons_printf ("\n  %-10s delta=0x%02x type=%s", vari->name,
							vari->delta, r_anal_var_type_to_str (core->anal, vari->type));
					r_cons_printf ("\n  diff: type=%s",
							fcni->diff->type==R_ANAL_DIFF_TYPE_MATCH?"match":
							fcni->diff->type==R_ANAL_DIFF_TYPE_UNMATCH?"unmatch":"new");
					if (fcni->diff->addr != -1)
						r_cons_printf (" addr=0x%"PFMT64x, fcni->diff->addr);
					if (fcni->diff->name != NULL)
						r_cons_printf (" function=%s",
							fcni->diff->name);
				}
				r_cons_newline ();
			} else r_cons_printf ("af+ 0x%08"PFMT64x" %"PFMT64d" %s %c %c\n",
						fcni->addr, fcni->size, fcni->name,
						fcni->type==R_ANAL_FCN_TYPE_LOC?'l':'f',
						fcni->diff->type==R_ANAL_DIFF_TYPE_MATCH?'m':
						fcni->diff->type==R_ANAL_DIFF_TYPE_UNMATCH?'u':'n');
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
	if (pbb) r_list_free (pbb);
	r_cons_printf ("}\n");
	r_cons_flush ();
	r_config_set_i (core->config, "asm.lines", reflines);
	r_config_set_i (core->config, "asm.bytes", bytes);
	r_config_set_i (core->config, "asm.dwarf", dwarf);
	return R_TRUE;
}

static int r_core_anal_followptr(RCore *core, ut64 at, ut64 ptr, ut64 ref, int code, int depth) {
	ut64 dataptr;
	int wordsize, endian;

	if (ptr == ref) {
		if (code)
			r_cons_printf ("ar 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
					(ut64)ref, (ut64)at);
		else r_cons_printf ("ard 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
					(ut64)ref, (ut64)at);
		return R_TRUE;
	}
	if (depth < 1)
		return R_FALSE;
	if (core->bin->curarch.info->big_endian)
		endian = !LIL_ENDIAN;
	else endian = LIL_ENDIAN;
	wordsize = (int)(core->anal->bits/8);
	if ((dataptr = r_io_read_i (core->io, ptr, wordsize, endian)) == -1) {
		return R_FALSE;
	}
	return r_core_anal_followptr (core, at, dataptr, ref, code, depth-1);
}

#define OPSZ 8
R_API int r_core_anal_search(RCore *core, ut64 from, ut64 to, ut64 ref) {
	ut8 *buf = (ut8 *)malloc (core->blocksize);
	int ptrdepth = r_config_get_i (core->config, "anal.ptrdepth");
	int ret, i, count = 0;
	RAnalOp op;
	ut64 at;
	// TODO: get current section range here or gtfo
	// ???
	// XXX must read bytes correctly
	if (buf==NULL)
		return -1;
	r_io_set_fd (core->io, core->file->fd);
	if (ref==0LL)
		eprintf ("Null reference search is not supported\n");
	else
	if (core->blocksize<=OPSZ)
		eprintf ("error: block size too small\n");
	else
		for (at = from; at < to; at += core->blocksize - OPSZ) {
			if (r_cons_singleton ()->breaked)
				break;
			ret = r_io_read_at (core->io, at, buf, core->blocksize);
			if (ret != core->blocksize)
				break;
			for (i=0; i<core->blocksize-OPSZ; i++) {
				if (!r_anal_aop (core->anal, &op, at+i, buf+i, core->blocksize-i))
					continue;
				if (op.type == R_ANAL_OP_TYPE_JMP || op.type == R_ANAL_OP_TYPE_CJMP ||
					op.type == R_ANAL_OP_TYPE_CALL) {
					if (op.jump != -1 &&
						r_core_anal_followptr (core, at+i, op.jump, ref, R_TRUE, 0)) {
						count ++;
					}
				} else if (op.type == R_ANAL_OP_TYPE_UJMP || op.type == R_ANAL_OP_TYPE_UCALL) {
					if (op.ref != -1 &&
						r_core_anal_followptr (core, at+i, op.ref, ref, R_TRUE, 1)) {
						count ++;
					}
				} else {
					if (op.ref != -1 &&
						r_core_anal_followptr (core, at+i, op.ref, ref, R_FALSE, ptrdepth)) {
						count ++;
					}
				}
			}
		}
	free (buf);
	return count;
}

R_API int r_core_anal_ref_list(RCore *core, int rad) {
	RAnalFcn *fcni;
	struct r_anal_ref_t *refi;
	RListIter *iter, *iter2;

	r_list_foreach (core->anal->fcns, iter, fcni)
		r_list_foreach (fcni->refs, iter2, refi) {
			if (rad)
			r_cons_printf ("ar%s 0x%08"PFMT64x" 0x%08"PFMT64x"\n", 
						refi->type==R_ANAL_REF_TYPE_DATA?"d":"",
						refi->at, refi->addr);
			else r_cons_printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x" (%c)\n", 
					refi->at, refi->addr, refi->type);

		}
	r_list_foreach (core->anal->refs, iter2, refi) {
		if (rad)
			r_cons_printf ("ar%s 0x%08"PFMT64x" 0x%08"PFMT64x"\n", 
					refi->type==R_ANAL_REF_TYPE_DATA?"d":"",
					refi->at, refi->addr);
		else r_cons_printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x" (%c)\n", 
				refi->at, refi->addr, refi->type);

	}
	r_cons_flush ();
	return R_TRUE;
}

R_API int r_core_anal_fcn_cc(RCore *core, ut64 addr) {
	RList *pbb;
	int ret;

	pbb = r_anal_bb_list_new ();
	if (!pbb)
		return -1;
	ret = fcn_cc (core, pbb, addr);
	r_list_free (pbb);
	return ret;
}

R_API int r_core_anal_all(RCore *core) {
	RList *list;
	RListIter *iter;
	RBinAddr *binmain;
	RBinAddr *entry;
	RBinSymbol *symbol;
	RAnalFcn *fcn;
	ut64 baddr;
	int depth =r_config_get_i (core->config, "anal.depth"); 
	int va = core->io->va || core->io->debug;

	baddr = r_bin_get_baddr (core->bin);
	/* Analyze Functions */
	/* Main */
	if ((binmain = r_bin_get_sym (core->bin, R_BIN_SYM_MAIN)) != NULL)
		r_core_anal_fcn (core, va?baddr+binmain->rva:binmain->offset, -1,
				R_ANAL_REF_TYPE_NULL, depth);
	/* Entries */
	if ((list = r_bin_get_entries (core->bin)) != NULL)
		r_list_foreach (list, iter, entry)
			r_core_anal_fcn (core, va?baddr+entry->rva:entry->offset, -1,
					R_ANAL_REF_TYPE_NULL, depth);
	/* Symbols (Imports are already analized by rabin2 on init) */
	if ((list = r_bin_get_symbols (core->bin)) != NULL)
		r_list_foreach (list, iter, symbol)
			if (!strncmp (symbol->type,"FUNC", 4))
				r_core_anal_fcn (core, va?baddr+symbol->rva:symbol->offset, -1,
						R_ANAL_REF_TYPE_NULL, depth);
	/* Analyze Basic blocks */
	r_list_foreach (core->anal->fcns, iter, fcn)
		if (fcn->type == R_ANAL_FCN_TYPE_FCN)
			r_core_anal_bb (core, core->anal->bbs, fcn->addr, depth, R_TRUE);

	return R_TRUE;
}
