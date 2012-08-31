/* radare - LGPL - Copyright 2009-2012 - pancake, nibble */

#include <r_types.h>
#include <r_list.h>
#include <r_flags.h>
#include <r_core.h>

static char *r_core_anal_graph_label(RCore *core, RAnalBlock *bb, int opts) {
	char cmd[1024], file[1024], *cmdstr = NULL, *filestr = NULL, *str = NULL;
	int i, j, line = 0, oline = 0, idx = 0;
	ut64 at;

	if (opts & R_CORE_ANAL_GRAPHLINES) {
#if R_ANAL_BB_HA_OPS
		RAnalOp *opi;
		RListIter *iter;
		r_list_foreach (bb->ops, iter, opi) {
			r_bin_meta_get_line (core->bin, opi->addr, file, sizeof (file)-1, &line);
#else
		for (at=bb->addr; at<bb->addr+bb->size; at+=2) {
			r_bin_meta_get_line (core->bin, at, file, sizeof (file)-1, &line);
#endif
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
		if (!(str = malloc (strlen(cmdstr)*2)))
			return NULL;
		for (i=j=0; cmdstr[i]; i++,j++) {
			switch (cmdstr[i]) {
			case 0x1b:
				/* skip ansi chars */
				for (i++; cmdstr[i] && cmdstr[i]!='m' && cmdstr[i]!='H' && cmdstr[i]!='J'; i++);
				j--;
				break;
			case '"':
				str[j] = '\\';
				str[++j] = '"';
				break;
			case '\n':
			case '\r':
				str[j] = '\\';
				str[++j] = 'l';
				break;
			default:
				str[j] = cmdstr[i];
			}
		}
		str[j] = '\0';
		free (cmdstr);
	}
	return str;
}

static void r_core_anal_graph_nodes(RCore *core, RAnalFunction *fcn, int opts) {
	struct r_anal_bb_t *bbi;
	RListIter *iter;
	char *str;

	r_list_foreach (fcn->bbs, iter, bbi) {
		if (bbi->jump != -1) {
			r_cons_printf ("\t\"0x%08"PFMT64x"_0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"_0x%08"PFMT64x"\" "
					"[color=\"%s\"];\n", fcn->addr, bbi->addr, fcn->addr, bbi->jump,
					bbi->fail != -1 ? "green" : "blue");
			r_cons_flush ();
		}
		if (bbi->fail != -1) {
			r_cons_printf ("\t\"0x%08"PFMT64x"_0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"_0x%08"PFMT64x"\" "
				"[color=\"red\"];\n", fcn->addr, bbi->addr, fcn->addr, bbi->fail);
			r_cons_flush ();
		}
		if ((str = r_core_anal_graph_label (core, bbi, opts))) {
			if (opts & R_CORE_ANAL_GRAPHDIFF) {
				r_cons_printf (" \"0x%08"PFMT64x"_0x%08"PFMT64x"\" [color=\"%s\","
					" label=\"%s\", URL=\"%s/0x%08"PFMT64x"\"]\n",
					fcn->addr, bbi->addr, 
					bbi->diff->type==R_ANAL_DIFF_TYPE_MATCH? "lightgray":
					bbi->diff->type==R_ANAL_DIFF_TYPE_UNMATCH? "yellow": "red", str,
					fcn->name, bbi->addr);
			} else {
				r_cons_printf (" \"0x%08"PFMT64x"_0x%08"PFMT64x"\" ["
					"URL=\"%s/0x%08"PFMT64x"\" color=\"%s\", label=\"%s\"]\n",
					fcn->addr, bbi->addr, 
					fcn->name, bbi->addr,
					bbi->traced?"yellow":"lightgray", str);
			}
			r_cons_flush ();
			free (str);
		}
	}
}

R_API int r_core_anal_bb(RCore *core, RAnalFunction *fcn, ut64 at, int head) {
	struct r_anal_bb_t *bb = NULL, *bbi;
	RListIter *iter;
	ut64 jump, fail;
	ut8 *buf = NULL;
	int ret = R_ANAL_RET_NEW, buflen, bblen = 0;
	int split = core->anal->split;

	if (--fcn->depth<=0)
		return R_FALSE;
	if (!(bb = r_anal_bb_new ()))
		return R_FALSE;
	if (split) ret = r_anal_fcn_split_bb (fcn, bb, at);
	else r_list_foreach (fcn->bbs, iter, bbi) {
		if (at == bbi->addr)
			ret = R_ANAL_RET_DUP;
	}
	if (ret == R_ANAL_RET_DUP) { /* Dupped bb */
		goto error;
	} else if (ret == R_ANAL_RET_NEW) { /* New bb */
		// XXX: use static buffer size of 512 or so
		if (!(buf = malloc (core->blocksize)))
			goto error;
		do {
#if 1
			// check io error
			if (r_io_read_at (core->io, at+bblen, buf, 4) != 4)
	//core->blocksize)) != core->blocksize)
				goto error;
#endif
			r_core_read_at (core, at+bblen, buf, core->blocksize);
			if (!memcmp (buf, "\xff\xff\xff\xff", 4))
				goto error;
			buflen = core->blocksize;
//eprintf ("Pre %llx %d\n", at, buflen);
			bblen = r_anal_bb (core->anal, bb, at+bblen, buf, buflen, head); 
//eprintf ("Pos %d\n", bblen);
			if (bblen == R_ANAL_RET_ERROR ||
				(bblen == R_ANAL_RET_END && bb->size < 1)) { /* Error analyzing bb */
				goto error;
			} else if (bblen == R_ANAL_RET_END) { /* bb analysis complete */
				if (split)
					ret = r_anal_fcn_overlap_bb (fcn, bb);
				if (ret == R_ANAL_RET_NEW) {
					r_list_append (fcn->bbs, bb);
					fail = bb->fail;
					jump = bb->jump;
					if (fail != -1)
						r_core_anal_bb (core, fcn, fail, R_FALSE);
					if (jump != -1)
						r_core_anal_bb (core, fcn, jump, R_FALSE);
				}
			}
		} while (bblen != R_ANAL_RET_END);
	}

	free (buf);
	return R_TRUE;

error:
	r_list_unlink (fcn->bbs, bb);
	r_anal_bb_free (bb);
	free (buf);
	return R_FALSE;
}

R_API int r_core_anal_bb_seek(RCore *core, ut64 addr) {
	RAnalBlock *bbi;
	RAnalFunction *fcni;
	RListIter *iter, *iter2;
	r_list_foreach (core->anal->fcns, iter, fcni)
		r_list_foreach (fcni->bbs, iter2, bbi)
			if (addr >= bbi->addr && addr < bbi->addr+bbi->size)
				return r_core_seek (core, bbi->addr, R_FALSE);
	return r_core_seek (core, addr, R_FALSE);
}

static int cmpaddr (void *_a, void *_b) {
	RAnalBlock *a = _a, *b = _b;
	return (a->addr > b->addr);
}

// XXX: This function takes sometimes forever
R_API int r_core_anal_fcn(RCore *core, ut64 at, ut64 from, int reftype, int depth) {
	RListIter *iter, *iter2;
	int buflen, fcnlen = 0;
	RAnalFunction *fcn = NULL, *fcni;
	RAnalRef *ref = NULL, *refi;
	ut64 *next = NULL;
	int i, nexti = 0;
	ut8 *buf;
#define ANALBS 256

	if (at>>63 == 1)
		return R_FALSE;
	if (at == UT64_MAX)
		return R_FALSE;
	if (depth < 0)
		return R_FALSE;
#warning This must be optimized to use the fcnstore api
	r_list_foreach (core->anal->fcns, iter, fcni) {
		if (r_cons_singleton ()->breaked)
			break;
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
	}
	if (!(fcn = r_anal_fcn_new ())) {
		eprintf ("Error: new (fcn)\n");
		return R_FALSE;
	}
	if (!(buf = malloc (ANALBS))) { //core->blocksize))) {
		eprintf ("Error: malloc (buf)\n");
		goto error;
	}
#define MAXNEXT 1032 // TODO: make it relocatable
	if (r_config_get_i (core->config, "anal.hasnext")) {
		
		next = R_NEWS0 (ut64, MAXNEXT);
	}

	//eprintf ("FUNC 0x%08"PFMT64x"\n", at+fcnlen);
	do {
		// check io error
		if ((buflen = r_io_read_at (core->io, at+fcnlen, buf, 4) != 4))
			goto error;
		// real read.
		if (!r_core_read_at (core, at+fcnlen, buf, ANALBS))
			goto error;
		if (!memcmp (buf, "\xff\xff\xff\xff", 4))
			goto error;
		buflen = ANALBS;
		if (r_cons_singleton ()->breaked)
			break;
		fcnlen = r_anal_fcn (core->anal, fcn, at+fcnlen, buf, buflen, reftype);
		if (fcnlen == R_ANAL_RET_ERROR ||
			(fcnlen == R_ANAL_RET_END && fcn->size < 1)) { /* Error analyzing function */
			goto error;
		} else if (fcnlen == R_ANAL_RET_END) { /* Function analysis complete */
			RFlagItem *f = r_flag_get_i (core->flags, at);
			if (f) { /* Check if it's already flagged */
				fcn->name = strdup (f->name);
			} else {
				fcn->name = r_str_dup_printf ("%s.%08"PFMT64x,
						fcn->type == R_ANAL_FCN_TYPE_LOC? "loc":
						fcn->type == R_ANAL_FCN_TYPE_SYM? "sym":
						fcn->type == R_ANAL_FCN_TYPE_IMP? "imp": "fcn", at);
				/* Add flag */
				r_flag_space_set (core->flags, "functions");
				r_flag_set (core->flags, fcn->name, at, fcn->size, 0);
			}
			/* TODO: Dupped analysis, needs more optimization */
		fcn->depth = 256;
			r_core_anal_bb (core, fcn, fcn->addr, R_TRUE);
// hack
		if (fcn->depth == 0) {
			eprintf ("Analysis depth reached at 0x%08"PFMT64x"\n", fcn->addr);
		} else fcn->depth = 256-fcn->depth;
			r_list_sort (fcn->bbs, &cmpaddr);

			/* New function: Add initial xref */
			if (from != -1) {
				if (!(ref = r_anal_ref_new ())) {
					eprintf ("Error: new (xref)\n");
					goto error;
				}
				ref->addr = from;
				ref->at = at;
				ref->type = reftype;
				r_list_append (fcn->xrefs, ref);
			}
			// XXX: this looks weird
			r_anal_fcn_insert (core->anal, fcn);
#if 1
	if (next && nexti<MAXNEXT) {
		int i;
		ut64 addr = fcn->addr + fcn->size;
		for (i=0;i<nexti;i++)
			if (next[i] == addr)
				break;
		if (i==nexti) {
			// TODO: ensure next address is function after padding (nop or trap or wat)
			eprintf ("FUNC 0x%08"PFMT64x" > 0x%08"PFMT64x"\r",
				fcn->addr, fcn->addr + fcn->size);
			next[nexti++] = fcn->addr + fcn->size;
		}
	}
#endif
			//r_list_append (core->anal->fcns, fcn);
			r_list_foreach (fcn->refs, iter, refi)
				if (refi->addr != -1)
					// TODO: fix memleak here, fcn not freed even though it is
					// added in core->anal->fcns which is freed in r_anal_free()
					r_core_anal_fcn (core, refi->addr, refi->at, refi->type, depth-1);
		}
	} while (fcnlen != R_ANAL_RET_END);
	free (buf);

	if (next) {
		for (i=0; i<nexti; i++) {
			if (!next[i]) continue;
			r_core_anal_fcn (core, next[i], from, 0, depth-1);
		}
		free (next);
	}

	return R_TRUE;

error:
	free (buf);
	// ugly hack to free fcn
	if (fcn) {
		if (fcn->size == 0 || fcn->addr == UT64_MAX) {
			r_anal_fcn_free (fcn);
			return R_FALSE;
		}
		// TODO: mark this function as not properly analyzed
		eprintf ("Analysis of function 0x%08"PFMT64x
			" has failed at 0x%08"PFMT64x"\n",
			fcn->addr, fcn->addr+fcn->size);
		if (!fcn->name) {
			// XXX dupped code.
			fcn->name = r_str_dup_printf ("%s.%08"PFMT64x,
					fcn->type == R_ANAL_FCN_TYPE_LOC? "loc":
					fcn->type == R_ANAL_FCN_TYPE_SYM? "sym":
					fcn->type == R_ANAL_FCN_TYPE_IMP? "imp": "fcn", at);
			/* Add flag */
			r_flag_space_set (core->flags, "functions");
			r_flag_set (core->flags, fcn->name, at, fcn->size, 0);
		}
		r_anal_fcn_insert (core->anal, fcn);
#if 0
		// unlink from list to avoid double free later when we call r_anal_free()
		r_list_unlink (core->anal->fcns, fcn);
		if (core->anal->fcns->free == NULL)
			r_anal_fcn_free (fcn);
#endif
	}
	if (next) {
		if (nexti<MAXNEXT)
			next[nexti++] = fcn->addr + fcn->size;
		for (i=0; i<nexti; i++) {
			if (!next[i]) continue;
			r_core_anal_fcn (core, next[i], next[i], 0, depth-1);
		}
		free(next);
	}
	return R_FALSE;
}

R_API int r_core_anal_fcn_clean(RCore *core, ut64 addr) {
	RAnalFunction *fcni;
	RListIter *iter, *iter_tmp;

	if (addr == 0) {
		r_list_destroy (core->anal->fcns);
		if (!(core->anal->fcns = r_anal_fcn_list_new ()))
			return R_FALSE;
	} else {
		r_list_foreach_safe (core->anal->fcns, iter, iter_tmp, fcni) {
			if (addr >= fcni->addr && addr < fcni->addr+fcni->size) {
				r_list_delete (core->anal->fcns, iter);
			}
		}
	}
	return R_TRUE;
}

R_API void r_core_anal_refs(RCore *core, ut64 addr, int gv) {
	const char *font = r_config_get (core->config, "graph.font");
	RListIter *iter, *iter2;
	RAnalRef *fcnr;
	RAnalFunction *fcni;
	int showhdr = 0;

	r_list_foreach (core->anal->fcns, iter, fcni) {
		if (addr != 0 && addr != fcni->addr)
			continue;
		if (!gv) r_cons_printf ("0x%08"PFMT64x"\n", fcni->addr);
		r_list_foreach (fcni->refs, iter2, fcnr) {
			if (!showhdr) {
				if (gv) r_cons_printf ("digraph code {\n"
					"\tgraph [bgcolor=white];\n"
					"\tnode [color=lightgray, style=filled shape=box"
					" fontname=\"%s\" fontsize=\"8\"];\n", font);
				showhdr = 1;
			}
			// TODO: display only code or data refs?
			RFlagItem *flag = r_flag_get_i (core->flags, fcnr->addr);
			if (gv) {
				r_cons_printf ("\t\"0x%08"PFMT64x"\" -> \"0x%08"PFMT64x"\" "
					"[label=\"%s\" color=\"%s\" URL=\"%s/0x%08"PFMT64x"\"];\n",
					fcni->addr, fcnr->addr, flag?flag->name:"",
					(fcnr->type==R_ANAL_REF_TYPE_CODE ||
					 fcnr->type==R_ANAL_REF_TYPE_CALL)?"green":"red",
					flag?flag->name:"", fcnr->addr);
				r_cons_printf ("\t\"0x%08"PFMT64x"\" "
					"[label=\"%s\" URL=\"%s/0x%08"PFMT64x"\"];\n",
					fcnr->addr, flag?flag->name:"",
					flag?flag->name:"", fcnr->addr);
			}
			else r_cons_printf (" - 0x%08"PFMT64x" (%c)\n", fcnr->addr, fcnr->type);
		}
	}
	if (showhdr && gv)
		r_cons_printf ("}\n");
}

static void fcn_list_bbs(RAnalFunction *fcn) {
	RAnalBlock *bbi;
	RListIter *iter;

	r_list_foreach (fcn->bbs, iter, bbi) {
		r_cons_printf ("afb 0x%08"PFMT64x" 0x%08"PFMT64x" %04"PFMT64d" ",
				fcn->addr, bbi->addr, bbi->size);
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
	}
}

R_API int r_core_anal_fcn_list(RCore *core, const char *input, int rad) {
	RAnalFunction *fcni;
	struct r_anal_ref_t *refi;
	struct r_anal_var_t *vari;
	RListIter *iter, *iter2;
	ut64 addr = r_num_math (core->num, input+1);

	r_list_foreach (core->anal->fcns, iter, fcni)
		if (((input == NULL || *input == '\0') && fcni->type!=R_ANAL_FCN_TYPE_LOC)
			 || fcni->addr == addr
			 || !strcmp (fcni->name, input+1)) {
			if (!rad) {
				r_cons_printf ("[0x%08"PFMT64x"] size=%"PFMT64d" name=%s",
						fcni->addr, fcni->size, fcni->name);
				r_cons_printf (" type=%s",
						fcni->type==R_ANAL_FCN_TYPE_SYM?"sym":
						fcni->type==R_ANAL_FCN_TYPE_IMP?"imp":"fcn");
				if (fcni->type==R_ANAL_FCN_TYPE_FCN || fcni->type==R_ANAL_FCN_TYPE_SYM)
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

				if (fcni->type==R_ANAL_FCN_TYPE_FCN || fcni->type==R_ANAL_FCN_TYPE_SYM) {
					r_cons_printf ("\n  vars:");
					r_list_foreach (fcni->vars, iter2, vari)
						r_cons_printf ("\n  %-10s delta=0x%02x type=%s", vari->name,
							vari->delta, r_anal_type_to_str (core->anal, vari->type, ";"));
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
			} else {
				r_cons_printf ("af+ 0x%08"PFMT64x" %"PFMT64d" %s %c %c\n",
						fcni->addr, fcni->size, fcni->name,
						fcni->type==R_ANAL_FCN_TYPE_LOC?'l':
						fcni->type==R_ANAL_FCN_TYPE_SYM?'s':
						fcni->type==R_ANAL_FCN_TYPE_IMP?'i':'f',
						fcni->diff->type==R_ANAL_DIFF_TYPE_MATCH?'m':
						fcni->diff->type==R_ANAL_DIFF_TYPE_UNMATCH?'u':'n');
				fcn_list_bbs (fcni);
			}
		}
	return R_TRUE;
}

static RList *recurse(RCore *core, RAnalBlock *from, RAnalBlock *dest);

static RList *recurse_bb(RCore *core, ut64 addr, RAnalBlock *dest) {
	RAnalBlock *bb;
	RList *ret;
	bb = r_anal_bb_from_offset (core->anal, addr);
	if (bb == dest) {
		eprintf ("path found!");
		return NULL;
	}
	ret = recurse (core, bb, dest);
	if (ret) return ret;
	return NULL;
}

static void register_path (RList *l) {
}

static RList *recurse(RCore *core, RAnalBlock *from, RAnalBlock *dest) {
	RList *ret = recurse_bb (core, from->jump, dest);
	if (ret) register_path (ret);
	ret = recurse_bb (core, from->fail, dest);
	if (ret) register_path (ret);

	/* same for all calls */
	// TODO: RAnalBlock must contain a linked list of calls
	return NULL;
}

R_API RList* r_core_anal_graph_to(RCore *core, ut64 addr, int n) {
	RAnalBlock *bb, *root = NULL, *dest = NULL;
	RListIter *iter, *iter2;
	RList *list2 = NULL, *list = NULL;
	RAnalFunction *fcn;

	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (!r_anal_fcn_is_in_offset (fcn, core->offset))
			continue;
		r_list_foreach (fcn->bbs, iter2, bb) {
			if (r_anal_bb_is_in_offset (bb, addr)) {
				dest = bb;
			}
			if (r_anal_bb_is_in_offset (bb, core->offset)) {
				root = bb;
		//		list2 = r_core_anal_graph_
				r_list_append (list, list2);
			}
		}
	}
	if (root && dest) {
		if (dest == root) {
			eprintf ("Source and destination are the same\n");
			return NULL;
		}
		eprintf ("ROOT BB 0x%08"PFMT64x"\n", root->addr);
		eprintf ("DEST BB 0x%08"PFMT64x"\n", dest->addr);
		list = r_list_new ();
		/* {
			RList *ll = recurse (core, root, dest);
			r_list_append (list, ll);
		} */
		printf ("=>  0x%08"PFMT64x"\n", root->jump);
	} else eprintf ("Unable to find source or destination basic block\n");
	return list;
}

R_API int r_core_anal_graph(RCore *core, ut64 addr, int opts) {
	RAnalFunction *fcni;
	RListIter *iter;
	int reflines, bytes, dwarf;
	const char *font = r_config_get (core->config, "graph.font");

	if (r_list_empty (core->anal->fcns))
		return R_FALSE;

	reflines = r_config_get_i (core->config, "asm.lines");
	bytes = r_config_get_i (core->config, "asm.bytes");
	dwarf = r_config_get_i (core->config, "asm.dwarf");
	r_config_set_i (core->config, "asm.lines", 0);
	r_config_set_i (core->config, "asm.bytes", 0);
	r_config_set_i (core->config, "asm.dwarf", 0);
	r_cons_printf ("digraph code {\n"
		"\tgraph [bgcolor=white];\n"
		"\tnode [color=lightgray, style=filled shape=box"
		" fontname=\"%s\" fontsize=\"8\"];\n", font);
	r_cons_flush ();
	r_list_foreach (core->anal->fcns, iter, fcni)
		if (fcni->type & (R_ANAL_FCN_TYPE_SYM | R_ANAL_FCN_TYPE_FCN) &&
			(addr == 0 || addr == fcni->addr))
			r_core_anal_graph_nodes (core, fcni, opts);
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
		if (code) r_cons_printf ("ar 0x%08"PFMT64x" 0x%08"PFMT64x"\n", (ut64)ref, (ut64)at);
		else r_cons_printf ("ard 0x%08"PFMT64x" 0x%08"PFMT64x"\n", (ut64)ref, (ut64)at);
		return R_TRUE;
	}
	if (depth < 1)
		return R_FALSE;
	if (core->bin->cur.o->info->big_endian)
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
	RAnalOp op = {0};
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
				r_anal_op_fini (&op);
				if (!r_anal_op (core->anal, &op, at+i, buf+i, core->blocksize-i))
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
	r_anal_op_fini (&op);
	return count;
}

R_API int r_core_anal_ref_list(RCore *core, int rad) {
	RAnalFunction *fcni;
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
		if (rad) r_cons_printf ("ar%s 0x%08"PFMT64x" 0x%08"PFMT64x"\n",
					refi->type==R_ANAL_REF_TYPE_DATA?"d":"",
					refi->at, refi->addr);
		else r_cons_printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x" (%c)\n",
				refi->at, refi->addr, refi->type);
	}
	r_cons_flush ();
	return R_TRUE;
}

R_API int r_core_anal_all(RCore *core) {
	RList *list;
	RListIter *iter;
	RAnalFunction *fcni;
	RBinAddr *binmain;
	RBinAddr *entry;
	RBinSymbol *symbol;
	ut64 baddr;
	ut64 offset;
	int depth =r_config_get_i (core->config, "anal.depth");
	int va = core->io->va || core->io->debug;

	baddr = r_bin_get_baddr (core->bin);
	offset = r_bin_get_offset (core->bin);
	/* Analyze Functions */
	/* Main */
	if ((binmain = r_bin_get_sym (core->bin, R_BIN_SYM_MAIN)) != NULL)
		r_core_anal_fcn (core, offset + va?baddr+binmain->rva:binmain->offset, -1,
				R_ANAL_REF_TYPE_NULL, depth);
	/* Entries */
	{
	RFlagItem *item = r_flag_get (core->flags, "entry0");
	if (item)
		r_core_anal_fcn (core, item->offset, -1, R_ANAL_REF_TYPE_NULL, depth);
	}
	if ((list = r_bin_get_entries (core->bin)) != NULL)
		r_list_foreach (list, iter, entry)
			r_core_anal_fcn (core, offset + va? baddr+entry->rva:entry->offset, -1,
					R_ANAL_REF_TYPE_NULL, depth);
	/* Symbols (Imports are already analized by rabin2 on init) */
	if ((list = r_bin_get_symbols (core->bin)) != NULL)
		r_list_foreach (list, iter, symbol) {
			if (core->cons->breaked)
				break;
			if (!strncmp (symbol->type, "FUNC", 4))
				r_core_anal_fcn (core, offset + va?baddr+symbol->rva:symbol->offset, -1,
						R_ANAL_REF_TYPE_NULL, depth);
		}
	/* Set fcn type to R_ANAL_FCN_TYPE_SYM for symbols */
	r_list_foreach (core->anal->fcns, iter, fcni) {
		if (core->cons->breaked)
			break;
		if (!memcmp (fcni->name, "sym.", 4) || !memcmp (fcni->name, "main", 4))
			fcni->type = R_ANAL_FCN_TYPE_SYM;
	}
	return R_TRUE;
}
