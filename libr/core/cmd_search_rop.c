/* radare - LGPL - Copyright 2009-2016 - Alexandru Caciulescu */

#include <stddef.h>

#include "r_core.h"
#include "r_io.h"
#include "r_list.h"
#include "r_types_base.h"

static RList* parse_list (const char *str) {
	RList *list;
	char *line, *data, *p, *str_n;

	if (!str) {
		return NULL;
	}

	str_n = strdup (str);
	list = r_list_newf (free);
	line = strtok (str_n, "\n");
	data = strchr (line, '=');
	p = strtok (data + 1, ",");

	while (p) {
		r_list_append (list, (void*)strdup (p));
		p = strtok (NULL, ",");
	}

	free (str_n);
	return list;
}

static RList* get_constants (const char *str) {
	RList *list;
	char *p, *data;

	if (!str) {
		return NULL;
	}

	data = strdup (str);
	list = r_list_newf (free);
	p = strtok (data, ",");

	while (p) {
		if (strtol (p, NULL, 0)) {
			r_list_append (list, (void*)strdup (p));
		}
		p = strtok (NULL, ",");
	}

	return list;
}

static char* rop_classify_constant (RCore *core, RList *ropList) {
	char *esil_str, *constant;
	char *mov = NULL;
	RListIter *iter_src, *iter_r, *iter_dst, *iter_const;
	RRegItem *item_dst;
	RList *head, *constants;
	RList *ops_list = NULL, *flg_read = NULL, *flg_write = NULL, *reg_read = NULL,
		*reg_write = NULL, *mem_read = NULL, *mem_write = NULL;
	const bool romem = r_config_get_i (core->config, "esil.romem");
	const bool stats = r_config_get_i (core->config, "esil.stats");

	if (!romem || !stats) {
		// eprintf ("Error: esil.romem and esil.stats must be set TRUE");
		return NULL;
	}

	r_list_foreach (ropList, iter_r, esil_str) {
		if (strchr (esil_str, '[')) { // avoid MEM read/write for now
			return NULL;
		}

		constants = get_constants (esil_str);
		// if there are no constants in the instruction continue
		if (!constants || !constants->head) {
			continue;
		}

		// init regs with random values
		head = r_reg_get_list (core->dbg->reg, 0);
		if (!head) {
			return NULL;
		}
		r_list_foreach (head, iter_dst, item_dst) {
			int r = r_num_rand (30000);
			r_reg_set_value (core->dbg->reg, item_dst, r);
		}

		// r_cons_printf ("Emulating const pattern:%s\n", esil_str);
		cmd_anal_esil (core, esil_str);
		char *out = sdb_querys (core->anal->esil->stats, NULL, 0, "*");
		// r_cons_println (out);
		if (out) {
			ops_list = parse_list (strstr (out, "ops.list"));
			flg_read = parse_list (strstr (out, "flg.read"));
			flg_write = parse_list (strstr (out, "flg.write"));
			reg_read = parse_list (strstr (out, "reg.read"));
			reg_write = parse_list (strstr (out, "reg.write"));
			mem_read = parse_list (strstr (out, "mem.read"));
			mem_write = parse_list (strstr (out, "mem.write"));
		}

		if (!r_list_find (ops_list, "=", (RListComparator)strcmp)) {
			continue;
		}

		head = r_reg_get_list (core->dbg->reg, 0);
		if (!head) {
			return NULL;
		}
		r_list_foreach (head, iter_dst, item_dst) {
			ut64 diff_dst, value_dst;

			if (!r_list_find (reg_write, item_dst->name, (RListComparator)strcmp)) {
				continue;
			}

			value_dst = r_reg_get_value (core->dbg->reg, item_dst);
			r_reg_arena_swap (core->dbg->reg, false);
			diff_dst = r_reg_get_value (core->dbg->reg, item_dst);
			r_reg_arena_swap (core->dbg->reg, false);
			//restore initial value
			r_reg_set_value (core->dbg->reg, item_dst, diff_dst);

			if (value_dst != diff_dst) {
				r_list_foreach (constants, iter_const, constant) {
					// if (value_dst == strtol (constant, NULL, 0)) {
					if (value_dst == r_num_get (NULL, constant)) {
						mov = r_str_concatf (mov, "%s <-- 0x%"PFMT64x";", item_dst->name, value_dst);
					}
				}
			}
		}
		free (out);
	}

	return mov;
}

static char* rop_classify_mov (RCore *core, RList *ropList) {
	char *esil_str;
	char *mov = NULL;
	RListIter *iter_src, *iter_r, *iter_dst;
	RRegItem *item_src, *item_dst;
	RList *head;
	RList *ops_list = NULL, *flg_read = NULL, *flg_write = NULL, *reg_read = NULL,
		*reg_write = NULL, *mem_read = NULL, *mem_write = NULL;
	const bool romem = r_config_get_i (core->config, "esil.romem");
	const bool stats = r_config_get_i (core->config, "esil.stats");

	if (!romem || !stats) {
		// eprintf ("Error: esil.romem and esil.stats must be set TRUE");
		return NULL;
	}

	r_list_foreach (ropList, iter_r, esil_str) {
		if (strchr (esil_str, '[')) { // avoid MEM read/write for now
			return NULL;
		}

		// init regs with random values
		head = r_reg_get_list (core->dbg->reg, 0);
		if (!head) {
			return NULL;
		}
		r_list_foreach (head, iter_dst, item_dst) {
			int r = r_num_rand (30000);
			r_reg_set_value (core->dbg->reg, item_dst, r);
		}

		// r_cons_printf ("Emulating mov pattern:%s\n", esil_str);
		cmd_anal_esil (core, esil_str);
		char *out = sdb_querys (core->anal->esil->stats, NULL, 0, "*");
		// r_cons_println (out);
		if (out) {
			ops_list = parse_list (strstr (out, "ops.list"));
			flg_read = parse_list (strstr (out, "flg.read"));
			flg_write = parse_list (strstr (out, "flg.write"));
			reg_read = parse_list (strstr (out, "reg.read"));
			reg_write = parse_list (strstr (out, "reg.write"));
			mem_read = parse_list (strstr (out, "mem.read"));
			mem_write = parse_list (strstr (out, "mem.write"));
		}

		if (!r_list_find (ops_list, "=", (RListComparator)strcmp)) {
			continue;
		}

		head = r_reg_get_list (core->dbg->reg, 0);
		if (!head) {
			return NULL;
		}
		r_list_foreach (head, iter_dst, item_dst) {
			ut64 diff_dst, value_dst;

			if (!r_list_find (reg_write, item_dst->name, (RListComparator)strcmp)) {
				continue;
			}

			value_dst = r_reg_get_value (core->dbg->reg, item_dst);
			r_reg_arena_swap (core->dbg->reg, false);
			diff_dst = r_reg_get_value (core->dbg->reg, item_dst);
			r_reg_arena_swap (core->dbg->reg, false);
			//restore initial value
			r_reg_set_value (core->dbg->reg, item_dst, diff_dst);

			r_list_foreach (head, iter_src, item_src) {
				ut64 diff_src, value_src;

				if (!r_list_find (reg_read, item_src->name, (RListComparator)strcmp)) {
					continue;
				}
				if (item_src == item_dst) {
					continue;
				}

				value_src = r_reg_get_value (core->dbg->reg, item_src);
				r_reg_arena_swap (core->dbg->reg, false);
				diff_src = r_reg_get_value (core->dbg->reg, item_src);
				r_reg_arena_swap (core->dbg->reg, false);
				//restore initial value
				r_reg_set_value (core->dbg->reg, item_src, diff_src);

				if (value_dst == value_src && value_dst != diff_dst) {
					mov = r_str_concatf (mov, "%s <-- %s;", item_dst->name, item_src->name);
				}
			}
		}
		free (out);
	}

	return mov;
}

static int rop_classify_nops (RCore *core, RList *ropList) {
	char *esil_str;
	int changes = 1;
	RListIter *iter, *iter_r;
	RRegItem *item;
	RList *head;
	RList *ops_list = NULL, *flg_read = NULL, *flg_write = NULL, *reg_read = NULL,
		*reg_write = NULL, *mem_read = NULL, *mem_write = NULL;
	RHashTable *ht_old = r_hashtable_new ();
	RHashTable *ht_new = r_hashtable_new ();
	const bool romem = r_config_get_i (core->config, "esil.romem");
	const bool stats = r_config_get_i (core->config, "esil.stats");

	if (!romem || !stats) {
		// eprintf ("Error: esil.romem and esil.stats must be set TRUE");
		return -2;
	}

	// TODO: this seems useless ? should confirm
	// RReg *hack = core->dbg->reg;
	// core->dbg->reg = core->anal->reg;
	r_list_foreach (ropList, iter_r, esil_str) {
		if (strchr (esil_str, '[')) { // avoid MEM read/write for now
			return -1;
		}

		// r_cons_printf ("Emulating:%s\n", esil_str);
		cmd_anal_esil (core, esil_str);
		char *out = sdb_querys (core->anal->esil->stats, NULL, 0, "*");
		// r_cons_println (out);
		if (out) {
			ops_list = parse_list (strstr (out, "ops.list"));
			flg_read = parse_list (strstr (out, "flg.read"));
			flg_write = parse_list (strstr (out, "flg.write"));
			reg_read = parse_list (strstr (out, "reg.read"));
			reg_write = parse_list (strstr (out, "reg.write"));
			mem_read = parse_list (strstr (out, "mem.read"));
			mem_write = parse_list (strstr (out, "mem.write"));
		}
		// will work once we do MEM check
		// else {
			// directly say NOP
			// return changes;
		// }

		head = r_reg_get_list (core->dbg->reg, 0);
		if (!head) {
			return 0;
		}
		r_list_foreach (head, iter, item) {
			ut64 delta, diff, value;

			value = r_reg_get_value (core->dbg->reg, item);
			r_reg_arena_swap (core->dbg->reg, false);
			diff = r_reg_get_value (core->dbg->reg, item);
			r_reg_arena_swap (core->dbg->reg, false);
			delta = value - diff;
			//restore initial value
			r_reg_set_value (core->dbg->reg, item, diff);

			if (delta != 0) {
				// r_cons_printf ("REG changed: %s ( %d --> %d) \n", item->name, diff, value);
				changes = 0;
			}
		}
		free (out);
	}
	// core->dbg->reg = hack;

	return changes;
}

R_API void rop_classify (RCore *core, Sdb *db, RList *ropList, const char *key, unsigned int size) {
	int nop = rop_classify_nops (core, ropList);
	char *mov;
	if (nop == 1) {
		char *str = r_str_newf ("0x%"PFMT64x"  -->  NOP", size);
		sdb_set (db, key, str, 0);
	} else if (nop == -1) {
		char *str = r_str_newf ("0x%"PFMT64x"  ------>  MEM access", size);
		sdb_set (db, key, str, 0);
	} else if (mov = rop_classify_mov (core, ropList)) {
		char *str = r_str_newf ("0x%"PFMT64x"  ---->  MOV { %s }", size, mov);
		free (mov);
		sdb_set (db, key, str, 0);
	} else if (mov = rop_classify_constant (core, ropList)) {
		char *str = r_str_newf ("0x%"PFMT64x"  ---->  LOAD CONST { %s }", size, mov);
		free (mov);
		sdb_set (db, key, str, 0);
	} else {
		sdb_num_set (db, key, size, 0);
	}
}
