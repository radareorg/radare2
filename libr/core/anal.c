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

	if (!core->anal.bbs)
		return R_FALSE;
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
	struct r_anal_bb_t *bb, *bbi;
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
