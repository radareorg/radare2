/* radare - LGPL - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_list.h>
#include <r_core.h>

static char *r_core_anal_graph_label (struct r_core_t *core, ut64 addr, ut64 size) {
	char cmd[1024], *cmdstr = NULL, *str = NULL;
	int i, j;

	snprintf (cmd, 1023, "pD %lli @ 0x%08llx", size, addr);
	if ((cmdstr = r_core_cmd_str(core, cmd))) {
		if (!(str = malloc(strlen(cmdstr)*2)))
			return NULL;
		for(i=j=0;cmdstr[i];i++,j++) {
			switch(cmdstr[i]) {
				case 0x1b:
					/* skip ansi chars */
					for(i++;cmdstr[i]&&cmdstr[i]!='m'&&cmdstr[i]!='H'&&cmdstr[i]!='J';i++);
					j--;
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

static void r_core_anal_graph_nodes (struct r_core_t *core, RList *pbb, ut64 addr) {
	struct r_anal_bb_t *bbi, *bbc;
	RListIter *iter;
	char *str;

	if (pbb) { /* In partial graphs test if the bb is already printed */
		iter = r_list_iterator (pbb);
		while (r_list_iter_next (iter)) {
			bbi = r_list_iter_get (iter);
			if (addr >= bbi->addr && addr < bbi->addr+bbi->size)
				return;
		}
	}

	iter = r_list_iterator (core->anal.bbs);
	while (r_list_iter_next (iter)) {
		bbi = r_list_iter_get (iter);
		if (addr == 0 || (addr >= bbi->addr && addr < bbi->addr+bbi->size)) {
			if (pbb) { /* Copy BB and append to the list of printed bbs */
				bbc = MALLOC_STRUCT (RAnalysisBB);
				memcpy (bbc, bbi, sizeof (RAnalysisBB));
				r_list_append (pbb, bbc);
			}
			if (bbi->jump != -1) {
				r_cons_printf ("\t\"0x%08llx\" -> \"0x%08llx\" [color=\"green\"];\n", bbi->addr, bbi->jump);
				r_cons_flush ();
				if (addr != 0) r_core_anal_graph_nodes (core, pbb, bbi->jump);
			}
			if (bbi->fail != -1) {
				r_cons_printf ("\t\"0x%08llx\" -> \"0x%08llx\" [color=\"red\"];\n", bbi->addr, bbi->fail);
				r_cons_flush ();
				if (addr != 0) r_core_anal_graph_nodes (core, pbb, bbi->fail);
			}
			if ((str = r_core_anal_graph_label (core, bbi->addr, bbi->size))) {
				r_cons_printf (" \"0x%08llx\" [label=\"%s\"]\n", bbi->addr, str);
				r_cons_flush ();
				free(str);
			}
		}
	}
}

R_API int r_core_anal_bb (struct r_core_t *core, ut64 at, int depth) {
	struct r_anal_bb_t *bb;
	ut64 jump, fail;
	ut8 *buf;
	int ret, buflen, bblen = 0;

	if (depth < 0)
		return R_FALSE;
	if (!(bb = r_anal_bb_new()))
		return R_FALSE;
	ret = r_anal_bb_split (&core->anal, bb, core->anal.bbs, at);
	if (ret == R_ANAL_RET_DUP) { /* Dupped bb */
		r_anal_bb_free (bb);
		return R_FALSE;
	} else if (ret == R_ANAL_RET_NEW) { /* New bb */
		if (!(buf = malloc (core->blocksize)))
			return R_FALSE;
		do {
			if ((buflen = r_io_read_at (&core->io, at+bblen, buf, core->blocksize)) == -1)
				return R_FALSE;
			bblen = r_anal_bb (&core->anal, bb, at+bblen, buf, buflen); 
			if (bblen == R_ANAL_RET_ERROR) { /* Error analyzing bb */
				r_anal_bb_free (bb);
				return R_FALSE;
			} else if (bblen == R_ANAL_RET_END) { /* bb analysis complete */
				if (r_anal_bb_overlap (&core->anal, bb, core->anal.bbs) == R_ANAL_RET_NEW) {
					r_list_append (core->anal.bbs, bb);
					fail = bb->fail;
					jump = bb->jump;
					if (fail != -1)
						r_core_anal_bb (core, fail, depth-1);
					if (jump != -1)
						r_core_anal_bb (core, jump, depth-1);
				}
			}
		} while (bblen != R_ANAL_RET_END);
		free (buf);
	}
	return R_TRUE;
}

R_API int r_core_anal_bb_clean (struct r_core_t *core, ut64 addr) {
	struct r_anal_bb_t *bbi;
	RListIter *iter;
	ut64 jump, fail;

	if (addr == 0) {
		r_list_destroy (core->anal.bbs);
		if (!(core->anal.bbs = r_anal_bb_list_new ()))
			return R_FALSE;
	} else {
		iter = r_list_iterator (core->anal.bbs);
		while (r_list_iter_next (iter)) {
			bbi = r_list_iter_get (iter);
			if (addr >= bbi->addr && addr < bbi->addr+bbi->size) {
				jump = bbi->jump;
				fail = bbi->fail;
				r_list_unlink (core->anal.bbs, bbi);
				if (fail != -1)
					r_core_anal_bb_clean (core, fail);
				if (jump != -1)
					r_core_anal_bb_clean (core, jump);
			}
		}
	}
	return R_TRUE;
}

R_API int r_core_anal_bb_add (struct r_core_t *core, ut64 addr, ut64 size, ut64 jump, ut64 fail) {
	struct r_anal_bb_t *bb, *bbi;
	RListIter *iter;

	iter = r_list_iterator (core->anal.bbs);
	while (r_list_iter_next (iter)) {
		bbi = r_list_iter_get (iter);
		if (addr >= bbi->addr && addr < bbi->addr+bbi->size)
			return R_FALSE;
	}
	if (!(bb = r_anal_bb_new ()))
		return R_FALSE;
	bb->addr = addr;
	bb->size = size;
	bb->jump = jump;
	bb->fail = fail;
	r_list_append (core->anal.bbs, bb);
	return R_TRUE;
}

R_API int r_core_anal_bb_list (struct r_core_t *core, int rad) {
	struct r_anal_bb_t *bbi;
	RListIter *iter;

	iter = r_list_iterator (core->anal.bbs);
	while (r_list_iter_next (iter)) {
		bbi = r_list_iter_get (iter);
		if (rad)
			r_cons_printf ("ab+ 0x%08llx %lli 0x%08llx 0x%08llx\n",
				bbi->addr, bbi->size, bbi->jump, bbi->fail);
		else r_cons_printf ("[0x%08llx] size=%lli jump=0x%08llx fail=0x%08llx\n",
				bbi->addr, bbi->size, bbi->jump, bbi->fail);
	}
	r_cons_flush();
	return R_TRUE;
}

R_API int r_core_anal_fcn (struct r_core_t *core, ut64 at, ut64 from, int depth) {
	struct r_anal_fcn_t *fcn, *fcni;
	struct r_anal_ref_t *refi;
	RListIter *iter;
	ut64 *call;
	ut8 *buf;
	int buflen, fcnlen = 0;

	if (depth < 0)
		return R_FALSE;
	iter = r_list_iterator (core->anal.fcns);
	while (r_list_iter_next (iter)) {
		fcni = r_list_iter_get (iter);
		if (at >= fcni->addr && at < fcni->addr+fcni->size)
			return R_FALSE;
	}
	eprintf ("Analysing: 0x%08llx\n", at);
	if (!(fcn = r_anal_fcn_new()))
		return R_FALSE;
	if (!(buf = malloc (core->blocksize)))
		return R_FALSE;
	do {
		if ((buflen = r_io_read_at (&core->io, at+fcnlen, buf, core->blocksize)) != core->blocksize)
			return R_FALSE;
		fcnlen = r_anal_fcn (&core->anal, fcn, at+fcnlen, buf, buflen); 
		if (fcnlen == R_ANAL_RET_ERROR) { /* Error analyzing function */
			r_anal_fcn_free (fcn);
			return R_FALSE;
		} else if (fcnlen == R_ANAL_RET_END) { /* function analysis complete */
			r_list_append (core->anal.fcns, fcn);
			iter = r_list_iterator (fcn->refs);
			while (r_list_iter_next (iter)) {
				refi = r_list_iter_get (iter);
				call = (ut64*)refi;
				if (*call != -1)
					r_core_anal_fcn (core, *call, at, depth-1);
			}
		}
	} while (fcnlen != R_ANAL_RET_END);
	free (buf);
	return R_TRUE;
}

R_API int r_core_anal_fcn_clean (struct r_core_t *core, ut64 addr) {
	struct r_anal_fcn_t *fcni;
	RListIter *iter;

	if (addr == 0) {
		r_list_destroy (core->anal.fcns);
		if (!(core->anal.fcns = r_anal_fcn_list_new ()))
			return R_FALSE;
	} else {
		iter = r_list_iterator (core->anal.fcns);
		while (r_list_iter_next (iter)) {
			fcni = r_list_iter_get (iter);
			if (addr >= fcni->addr && addr < fcni->addr+fcni->size)
				r_list_unlink (core->anal.fcns, fcni);
		}
	}
	return R_TRUE;
}

R_API int r_core_anal_fcn_add (struct r_core_t *core, ut64 addr, ut64 size, const char *name) {
	struct r_anal_fcn_t *fcn, *fcni;
	RListIter *iter;

	iter = r_list_iterator (core->anal.fcns);
	while (r_list_iter_next (iter)) {
		fcni = r_list_iter_get (iter);
		if (addr >= fcni->addr && addr < fcni->addr+fcni->size)
			return R_FALSE;
	}
	if (!(fcn = r_anal_fcn_new ()))
		return R_FALSE;
	fcn->addr = addr;
	fcn->size = size;
	fcn->name = strdup (name);
	r_list_append (core->anal.fcns, fcn);
	return R_TRUE;
}

R_API int r_core_anal_fcn_list (struct r_core_t *core, int rad) {
	struct r_anal_fcn_t *fcni;
	struct r_anal_ref_t *refi;
	RListIter *iter, *iter2;
	ut64 *call;

	iter = r_list_iterator (core->anal.fcns);
	while (r_list_iter_next (iter)) {
		fcni = r_list_iter_get (iter);
		if (rad)
			r_cons_printf ("af+ 0x%08llx %lli %s\n", fcni->addr, fcni->size, fcni->name);
		else {
			r_cons_printf ("[0x%08llx] size=%lli name=%s\n",
					fcni->addr, fcni->size, fcni->name);
			r_cons_printf ("refs: ");
			iter2 = r_list_iterator (fcni->refs);
			while (r_list_iter_next (iter)) {
				refi = r_list_iter_get (iter);
				call = (ut64*)refi;
				r_cons_printf ("0x%08llx ", *call);
			}
			r_cons_printf ("\n");
		}
	}
	r_cons_flush();
	return R_TRUE;
}

R_API int r_core_anal_graph (struct r_core_t *core, ut64 addr) {
	RList *pbb = NULL;
	int reflines = r_config_get_i(&core->config, "asm.reflines");
	int bytes = r_config_get_i(&core->config, "asm.bytes");

	r_config_set_i(&core->config, "asm.reflines", 0);
	r_config_set_i(&core->config, "asm.bytes", 0);
	r_cons_printf ("digraph code {\n");
	r_cons_printf ("\tgraph [bgcolor=white];\n");
	r_cons_printf ("\tnode [color=lightgray, style=filled shape=box fontname=\"Courier\" fontsize=\"8\"];\n");
	r_cons_flush ();
	if (addr != 0) pbb = r_anal_bb_list_new (); /* In partial graphs define printed bb list */
	r_core_anal_graph_nodes (core, pbb, addr);
	if (pbb) r_list_destroy (pbb);
	r_cons_printf ("}\n");
	r_cons_flush ();
	r_config_set_i(&core->config, "asm.reflines", reflines);
	r_config_set_i(&core->config, "asm.bytes", bytes);
	return R_TRUE;
}
