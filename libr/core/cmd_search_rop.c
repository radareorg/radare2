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
	if (!list) {
		free (str_n);
		return NULL;
	}
	line = strtok (str_n, "\n");
	data = strchr (line, '=');
	// TODO: use r_str_split()
	p = strtok (data + 1, ",");

	while (p) {
		r_list_append (list, (void*)strdup (p));
		p = strtok (NULL, ",");
	}

	free (str_n);
	return list;
}

static RList* get_constants(const char *str) {
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
	free (data);
	return list;
}

static bool isFlag (RRegItem *reg) {
	const char *type = r_reg_get_type (reg->type);

	if (!strcmp (type, "flg"))
		return true;
	return false;
}

// binary op
static bool simulate_op (const char *op, ut64 src1, ut64 src2, ut64 old_src1, ut64 old_src2, ut64 *result, int size) {
	ut64 limit;
	if (size == 64) {
		limit = UT64_MAX;
	} else {
		limit = 1ULL << size;
	}

	if (!strcmp (op, "^")) {
		*result =  src1 ^ src2;
		return true;
	}
	if (!strcmp (op, "+")) {
		*result = src1 + src2;
		return true;
	}
	if (!strcmp (op, "-")) {
		if (src2 > src1) {
			*result = limit + (src1 - src2);
		} else {
			*result = src1 - src2;
		}
		return true;
	}
	if (!strcmp (op, "*")) {
		*result = src1 * src2;
		return true;
	}
	if (!strcmp (op, "|")) {
		*result = src1 | src2;
		return true;
	}
	if (!strcmp (op, "/")) {
		*result = src1 / src2;
		return true;
	}
	if (!strcmp (op, "%")) {
		*result = src1 % src2;
		return true;
	}
	if (!strcmp (op, "<<")) {
		*result = src1 << src2;
		return true;
	}
	if (!strcmp (op, ">>")) {
		*result = src1 >> src2;
		return true;
	}
	if (!strcmp (op, "&")) {
		*result = src1 & src2;
		return true;
	}
	if (!strcmp (op, "+=")) {
		*result = old_src1 + src2;
		return true;
	}
	if (!strcmp (op, "-=")) {
		if (src2 > old_src1) {
			*result = limit + (old_src1 - src2);
		} else {
			*result = old_src1 - src2;
		}
		return true;
	}
	if (!strcmp (op, "*=")) {
		*result = old_src1 * src2;
		return true;
	}
	if (!strcmp (op, "/=")) {
		*result = old_src1 / src2;
		return true;
	}
	if (!strcmp (op, "%=")) {
		*result = old_src1 % src2;
		return true;
	}
	if (!strcmp (op, "<<")) {
		*result = src1 << src2;
		return true;
	}
	if (!strcmp (op, ">>")) {
		*result = src1 >> src2;
		return true;
	}
	if (!strcmp (op, "&=")) {
		*result = src1 & src2;
		return true;
	}
	if (!strcmp (op, "^=")) {
		*result = src1 ^ src2;
		return true;
	}
	if (!strcmp (op, "|=")) {
		*result = src1 | src2;
		return true;
	}
	return false;
}

// fill REGs with known values
static void fillRegisterValues (RCore *core) {
	RListIter *iter_reg;
	RList *regs;
	RRegItem *reg_item;
	int nr = 10;

	regs = r_reg_get_list (core->dbg->reg, R_REG_TYPE_GPR);
	if (!regs) {
		return;
	}
	r_list_foreach (regs, iter_reg, reg_item) {
		r_reg_arena_pop (core->dbg->reg);
		r_reg_set_value (core->dbg->reg, reg_item, nr);
		r_reg_arena_push (core->dbg->reg);
		nr += 3;
	}
}

// split esil string in flags part and main instruction
// hacky, only tested for x86, TODO: portable version
// NOTE: esil_main and esil_flg are heap allocated and must be freed by the caller
static void esil_split_flg (char *esil_str, char **esil_main, char **esil_flg) {
	char *split = strstr (esil_str, "f,=");
	const int kCommaHits = 2;
	int hits = 0;

	if (split) {
		while (hits != kCommaHits) {
			--split;
			if (*split == ',') {
				hits++;
			}
		}
		*esil_flg = strdup (++split);
		*esil_main = r_str_ndup (esil_str, strlen (esil_str) - strlen (*esil_flg) - 1);
	}
}

#define FREE_ROP  { \
	R_FREE (out); \
	R_FREE (esil_flg);       \
	R_FREE (esil_main);      \
	r_list_free (ops_list);  \
	ops_list = NULL; \
	r_list_free (flg_read);  \
	flg_read = NULL; \
	r_list_free (flg_write); \
	flg_write = NULL; \
	r_list_free (reg_read);  \
	reg_read = NULL; \
	r_list_free (reg_write); \
	reg_write = NULL; \
	r_list_free (mem_read);  \
	mem_read = NULL; \
	r_list_free (mem_write); \
	mem_write = NULL; \
}

static char* rop_classify_constant(RCore *core, RList *ropList) {
	char *esil_str, *constant;
	char *ct = NULL, *esil_main = NULL, *esil_flg = NULL, *out = NULL;
	RListIter *iter_r, *iter_dst, *iter_const;
	RRegItem *item_dst;
	RList *head, *constants;
	RList *ops_list = NULL, *flg_read = NULL, *flg_write = NULL,
	      *reg_read = NULL, *reg_write = NULL, *mem_read = NULL,
	      *mem_write = NULL;
	const bool romem = r_config_get_i (core->config, "esil.romem");
	const bool stats = r_config_get_i (core->config, "esil.stats");

	if (!romem || !stats) {
		// eprintf ("Error: esil.romem and esil.stats must be set TRUE");
		return NULL;
	}

	r_list_foreach (ropList, iter_r, esil_str) {
		constants = get_constants (esil_str);
		// if there are no constants in the instruction continue
		if (r_list_empty (constants)) {
			continue;
		}
		// init regs with known values
		fillRegisterValues (core);
		head = r_reg_get_list (core->dbg->reg, R_REG_TYPE_GPR);
		if (!head) {
			ct = NULL;
			goto continue_error;
		}
		esil_split_flg (esil_str, &esil_main, &esil_flg);
		cmd_anal_esil (core, esil_main? esil_main: esil_str);
		out = sdb_querys (core->anal->esil->stats, NULL, 0, "*");
		if (!out) {
			goto continue_error;
		}
		ops_list  = parse_list (strstr (out, "ops.list"));
		flg_read  = parse_list (strstr (out, "flg.read"));
		flg_write = parse_list (strstr (out, "flg.write"));
		reg_read  = parse_list (strstr (out, "reg.read"));
		reg_write = parse_list (strstr (out, "reg.write"));
		mem_read  = parse_list (strstr (out, "mem.read"));
		mem_write = parse_list (strstr (out, "mem.write"));
		if (!r_list_find (ops_list, "=", (RListComparator)strcmp)) {
			goto continue_error;
		}
		head = r_reg_get_list (core->dbg->reg, R_REG_TYPE_GPR);
		if (!head) {
			goto out_error;
		}
		r_list_foreach (head, iter_dst, item_dst) {
			ut64 diff_dst, value_dst;
			if (!r_list_find (reg_write, item_dst->name,
					  (RListComparator)strcmp)) {
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
					if (value_dst == r_num_get (NULL, constant)) {
						ct = r_str_appendf (ct, "%s <-- 0x%"PFMT64x";", item_dst->name, value_dst);
					}
				}
			}
		}
continue_error:
		// coverity may complain here but as long as the pointer is set back to
		// NULL is safe that is why is used R_FREE
		FREE_ROP;
		r_list_free (constants);
	}
	return ct;
out_error:
	FREE_ROP;	
	r_list_free (constants);
	return NULL;
}

static char* rop_classify_mov(RCore *core, RList *ropList) {
	char *esil_str;
	char *mov = NULL, *esil_main = NULL, *esil_flg = NULL, *out = NULL;
	RListIter *iter_src, *iter_r, *iter_dst;
	RRegItem *item_src, *item_dst;
	RList *head;
	RList *ops_list = NULL, *flg_read = NULL, *flg_write = NULL,
	      *reg_read = NULL, *reg_write = NULL, *mem_read = NULL,
	      *mem_write = NULL;
	const bool romem = r_config_get_i (core->config, "esil.romem");
	const bool stats = r_config_get_i (core->config, "esil.stats");

	if (!romem || !stats) {
		// eprintf ("Error: esil.romem and esil.stats must be set TRUE");
		return NULL;
	}

	r_list_foreach (ropList, iter_r, esil_str) {
		// init regs with known values
		fillRegisterValues (core);
		head = r_reg_get_list (core->dbg->reg, R_REG_TYPE_GPR);
		if (!head) {
			goto out_error;
		}
		esil_split_flg (esil_str, &esil_main, &esil_flg);
		cmd_anal_esil (core, esil_main? esil_main: esil_str);
		out = sdb_querys (core->anal->esil->stats, NULL, 0, "*");
		if (out) {
			ops_list  = parse_list (strstr (out, "ops.list"));
			flg_read  = parse_list (strstr (out, "flg.read"));
			flg_write = parse_list (strstr (out, "flg.write"));
			reg_read  = parse_list (strstr (out, "reg.read"));
			reg_write = parse_list (strstr (out, "reg.write"));
			mem_read  = parse_list (strstr (out, "mem.read"));
			mem_write = parse_list (strstr (out, "mem.write"));
		} else {
			goto continue_error;
		}

		if (!r_list_find (ops_list, "=", (RListComparator)strcmp)) {
			goto continue_error;
		}

		head = r_reg_get_list (core->dbg->reg, R_REG_TYPE_GPR);
		if (!head) {
			goto out_error;
		}
		r_list_foreach (head, iter_dst, item_dst) {
			ut64 diff_dst, value_dst;
			if (!r_list_find (reg_write, item_dst->name,
					  (RListComparator)strcmp)) {
				continue;
			}

			// you never mov into flags
			if (isFlag (item_dst)) {
				continue;
			}

			value_dst = r_reg_get_value (core->dbg->reg, item_dst);
			r_reg_arena_swap (core->dbg->reg, false);
			diff_dst = r_reg_get_value (core->dbg->reg, item_dst);
			r_reg_arena_swap (core->dbg->reg, false);
			r_list_foreach (head, iter_src, item_src) {
				ut64 diff_src, value_src;
				if (!r_list_find (reg_read, item_src->name,
						  (RListComparator)strcmp)) {
					continue;
				}
				// you never mov from flags
				if (item_src == item_dst || isFlag (item_src)) {
					continue;
				}
				value_src = r_reg_get_value (core->dbg->reg, item_src);
				r_reg_arena_swap (core->dbg->reg, false);
				diff_src = r_reg_get_value (core->dbg->reg, item_src);
				r_reg_arena_swap (core->dbg->reg, false);
				//restore initial value
				r_reg_set_value (core->dbg->reg, item_src, diff_src);
				if (value_dst == value_src && value_dst != diff_dst) {
					mov = r_str_appendf (mov, "%s <-- %s;",
						item_dst->name, item_src->name);
				}
			}
		}
continue_error:
		FREE_ROP;
	}
	return mov;
out_error:
	FREE_ROP;
	return NULL;
}

static char* rop_classify_arithmetic(RCore *core, RList *ropList) {
	char *esil_str, *op;
	char *arithmetic = NULL, *esil_flg = NULL, *esil_main = NULL,
	     *out = NULL;
	RListIter *iter_src1, *iter_src2, *iter_r, *iter_dst, *iter_ops;
	RRegItem *item_src1, *item_src2, *item_dst;
	RList *head;
	RList *ops_list = NULL, *flg_read = NULL, *flg_write = NULL,
	      *reg_read = NULL, *reg_write = NULL, *mem_read = NULL,
	      *mem_write  = NULL;
	const bool romem = r_config_get_i (core->config, "esil.romem");
	const bool stats = r_config_get_i (core->config, "esil.stats");
	ut64 *op_result = R_NEW0 (ut64);
	ut64 *op_result_r = R_NEW0 (ut64);

	if (!romem || !stats) {
		// eprintf ("Error: esil.romem and esil.stats must be set TRUE");
		free (op_result);
		free (op_result_r);
		return NULL;
	}

	r_list_foreach (ropList, iter_r, esil_str) {
		// init regs with known values
		fillRegisterValues (core);
		head = r_reg_get_list (core->dbg->reg, R_REG_TYPE_GPR);
		if (!head) {
			goto out_error;
		}
		esil_split_flg (esil_str, &esil_main, &esil_flg);
		if (esil_main) {
			cmd_anal_esil (core, esil_main);
		} else {
			cmd_anal_esil (core, esil_str);
		}
		out = sdb_querys (core->anal->esil->stats, NULL, 0, "*");
		// r_cons_println (out);
		if (!out) {
			goto continue_error;
		}
		ops_list  = parse_list (strstr (out, "ops.list"));
		flg_read  = parse_list (strstr (out, "flg.read"));
		flg_write = parse_list (strstr (out, "flg.write"));
		reg_read  = parse_list (strstr (out, "reg.read"));
		reg_write = parse_list (strstr (out, "reg.write"));
		mem_read  = parse_list (strstr (out, "mem.read"));
		mem_write = parse_list (strstr (out, "mem.write"));

		r_list_foreach (ops_list, iter_ops, op) {
			r_list_foreach (head, iter_src1, item_src1) {
				ut64 value_src1, diff_src1;

				value_src1 = r_reg_get_value (core->dbg->reg, item_src1);
				r_reg_arena_swap (core->dbg->reg, false);
				diff_src1 = r_reg_get_value (core->dbg->reg, item_src1);
				r_reg_arena_swap (core->dbg->reg, false);
				if (!r_list_find (reg_read, item_src1->name,
						  (RListComparator)strcmp)) {
					continue;
				}

				r_list_foreach (head, iter_src2, item_src2) {
					ut64 value_src2, diff_src2;
					value_src2 = r_reg_get_value (core->dbg->reg, item_src2);
					r_reg_arena_swap (core->dbg->reg, false);
					diff_src2 = r_reg_get_value (core->dbg->reg, item_src2);

					if (!r_list_find (reg_read, item_src2->name,
						    (RListComparator)strcmp)) {
						continue;
					}
					// TODO check condition
					if (iter_src1 == iter_src2) {
						continue;
					}

					r_list_foreach (head, iter_dst, item_dst) {
						ut64 value_dst;
						bool redundant = false, simulate, simulate_r;

						value_dst = r_reg_get_value (core->dbg->reg, item_dst);
						r_reg_arena_swap (core->dbg->reg, false);
						if (!r_list_find (reg_write, item_dst->name,
							    	(RListComparator)strcmp)) {
							continue;
						}
						// don't check flags for arithmetic
						if (isFlag (item_dst)) {
							continue;
						}
						simulate = simulate_op (op, value_src1, value_src2, diff_src1, diff_src2, op_result, item_dst->size);
						simulate_r = simulate_op (op, value_src2, value_src1, diff_src2, diff_src1, op_result_r, item_dst->size);
						if (/*value_src1 != 0 && value_src2 != 0 && */simulate && value_dst == *op_result) {
							// r_cons_println ("Debug: FOUND ONE !");
							char *tmp = r_str_newf ("%s <-- %s %s %s;", item_dst->name, item_src1->name, op, item_src2->name);
							if (arithmetic && !strstr (arithmetic, tmp)) {
								arithmetic = r_str_append (arithmetic, tmp);
							} else if (!arithmetic) {
								arithmetic = r_str_append (arithmetic, tmp);
							}
							free (tmp);
							redundant = true;
						} else if (!redundant /*&& value_src1 != 0 && value_src2 != 0*/ && simulate_r && value_dst == *op_result_r) {
							// r_cons_println ("Debug: FOUND ONE reversed!");
							char *tmp = r_str_newf ("%s <-- %s %s %s;", item_dst->name, item_src2->name, op, item_src1->name);
							if (arithmetic && !strstr (arithmetic, tmp)) {
								arithmetic = r_str_append (arithmetic, tmp);
							} else if (!arithmetic) {
								arithmetic = r_str_append (arithmetic, tmp);
							}
							free (tmp);
						}
					}
				}
			}
		}
continue_error:	
		FREE_ROP;
	}
	free (op_result);
	free (op_result_r);
	return arithmetic;
out_error:
	FREE_ROP;
	free (op_result);	
	free (op_result_r);
	return NULL;
}

static char* rop_classify_arithmetic_const(RCore *core, RList *ropList) {
	char *esil_str, *op, *constant;
	char *arithmetic = NULL, *esil_flg = NULL, *esil_main = NULL;
	RListIter *iter_src1, *iter_r, *iter_dst, *iter_ops, *iter_const;
	RRegItem *item_src1, *item_dst;
	RList *head, *constants;
	RList *ops_list = NULL, *flg_read = NULL, *flg_write = NULL, *reg_read = NULL,
		*reg_write = NULL, *mem_read = NULL, *mem_write = NULL;
	const bool romem = r_config_get_i (core->config, "esil.romem");
	const bool stats = r_config_get_i (core->config, "esil.stats");
	ut64 *op_result = R_NEW0 (ut64);
	ut64 *op_result_r = R_NEW0 (ut64);

	if (!romem || !stats) {
		// eprintf ("Error: esil.romem and esil.stats must be set TRUE");
		R_FREE (op_result);
		R_FREE (op_result_r);
		return NULL;
	}

	r_list_foreach (ropList, iter_r, esil_str) {
		constants = get_constants (esil_str);
		// if there are no constants in the instruction continue
		if (r_list_empty (constants)) {
			continue;
		}
		// init regs with known values
		fillRegisterValues (core);
		head = r_reg_get_list (core->dbg->reg, R_REG_TYPE_GPR);
		if (!head) {
			arithmetic = NULL;
			continue;
		}
		esil_split_flg (esil_str, &esil_main, &esil_flg);
		if (esil_main) {
			cmd_anal_esil (core, esil_main);
		} else {
			cmd_anal_esil (core, esil_str);
		}
		char *out = sdb_querys (core->anal->esil->stats, NULL, 0, "*");
		// r_cons_println (out);
		if (out) {
			ops_list  = parse_list (strstr (out, "ops.list"));
			flg_read  = parse_list (strstr (out, "flg.read"));
			flg_write = parse_list (strstr (out, "flg.write"));
			reg_read  = parse_list (strstr (out, "reg.read"));
			reg_write = parse_list (strstr (out, "reg.write"));
			mem_read  = parse_list (strstr (out, "mem.read"));
			mem_write = parse_list (strstr (out, "mem.write"));
		} else {
			R_FREE (op_result);
			R_FREE (op_result_r);
			goto continue_error;
		}

		r_list_foreach (ops_list, iter_ops, op) {
			r_list_foreach (head, iter_src1, item_src1) {
				ut64 value_src1, diff_src1;
				value_src1 = r_reg_get_value (core->dbg->reg, item_src1);
				r_reg_arena_swap (core->dbg->reg, false);
				diff_src1 = r_reg_get_value (core->dbg->reg, item_src1);
				r_reg_arena_swap (core->dbg->reg, false);

				if (!r_list_find (reg_read, item_src1->name,
						  (RListComparator)strcmp)) {
					continue;
				}
				r_list_foreach (head, iter_dst, item_dst) {
					ut64 value_dst, diff_dst;
					bool redundant = false, simulate, simulate_r;
					value_dst = r_reg_get_value (core->dbg->reg, item_dst);
					r_reg_arena_swap (core->dbg->reg, false);
					diff_dst = r_reg_get_value (core->dbg->reg, item_dst);
					r_reg_arena_swap (core->dbg->reg, false);
					if (!r_list_find (reg_write, item_dst->name,
						    (RListComparator)strcmp)) {
						continue;
					}
					// don't check flags for arithmetic
					if (isFlag (item_dst)) {
						continue;
					}
					if (value_dst != diff_dst) {
						r_list_foreach (constants, iter_const, constant) {
							ut64 value_ct = r_num_get (NULL, constant);
							simulate = simulate_op (op, value_src1, value_ct, 
							  			diff_src1, value_ct, op_result, 
									 	item_dst->size);
							simulate_r = simulate_op (op, value_ct, value_src1, 
							  			value_ct, diff_src1, op_result_r, 
										item_dst->size);
							if (simulate && op_result && value_dst == *op_result) {
								char *tmp = r_str_newf ("%s <-- %s %s %s;", item_dst->name, item_src1->name, op, constant);
								if (arithmetic && !strstr (arithmetic, tmp)) {
									arithmetic = r_str_append (arithmetic, tmp);
								} else if (!arithmetic) {
									arithmetic = r_str_append (arithmetic, tmp);
								}
								free (tmp);
								redundant = true;
							} else if (!redundant && simulate_r && value_dst == *op_result_r) {
								char *tmp = r_str_newf ("%s <-- %s %s %s;", item_dst->name, constant, op, item_src1->name);
								if (arithmetic && !strstr (arithmetic, tmp)) {
									arithmetic = r_str_append (arithmetic, tmp);
								} else if (!arithmetic) {
									arithmetic = r_str_append (arithmetic, tmp);
								}
								free (tmp);
							}
						}
					}
				}
			}
		}
continue_error:
		FREE_ROP;
		r_list_free (constants);
	}
	free (op_result);
	free (op_result_r);
	return arithmetic;
}

static int rop_classify_nops(RCore *core, RList *ropList) {
	char *esil_str;
	int changes = 1;
	RListIter *iter_r;
	const bool romem = r_config_get_i (core->config, "esil.romem");
	const bool stats = r_config_get_i (core->config, "esil.stats");

	if (!romem || !stats) {
		// eprintf ("Error: esil.romem and esil.stats must be set TRUE\n");
		return -2;
	}

	r_list_foreach (ropList, iter_r, esil_str) {
		fillRegisterValues (core);

		// r_cons_printf ("Emulating nop:%s\n", esil_str);
		cmd_anal_esil (core, esil_str);
		char *out = sdb_querys (core->anal->esil->stats, NULL, 0, "*");
		// r_cons_println (out);
		if (out) {
			free (out);
			return 0;
		}
		// directly say NOP
		continue;
	}

	return changes;
}

static void rop_classify (RCore *core, Sdb *db, RList *ropList, const char *key, unsigned int size) {
	int nop = 0;  rop_classify_nops (core, ropList);
	char *mov, *ct, *arithm, *arithm_ct, *str;
	Sdb *db_nop = sdb_ns (db, "nop", true);
	Sdb *db_mov = sdb_ns (db, "mov", true);
	Sdb *db_ct = sdb_ns (db, "const", true);
	Sdb *db_aritm = sdb_ns (db, "arithm", true);
	Sdb *db_aritm_ct = sdb_ns (db, "arithm_ct", true);

	if (!db_nop || !db_mov || !db_ct || !db_aritm || !db_aritm_ct) {
		eprintf ("Error: Could not create SDB 'rop' sub-namespaces\n");
		return;
	}
	nop = rop_classify_nops (core, ropList);
	mov = rop_classify_mov (core, ropList);
	ct = rop_classify_constant (core, ropList);
	arithm = rop_classify_arithmetic (core, ropList);
	arithm_ct = rop_classify_arithmetic_const (core, ropList);
	str = r_str_newf ("0x%u", size);

	if (nop == 1) {
		char *str_nop = r_str_newf ("%s NOP", str);
		sdb_set (db_nop, key, str_nop, 0);
		free (str_nop);
	} else {
		if (mov) {
			char *str_mov = r_str_newf ("%s MOV { %s }", str, mov);
			sdb_set (db_mov, key, str_mov, 0);
			free (str_mov);
			free (mov);
		}
		if (ct) {
			char *str_ct = r_str_newf ("%s LOAD_CONST { %s }", str, ct);
			sdb_set (db_ct, key, str_ct, 0);
			free (str_ct);
			free (ct);
		}
		if (arithm) {
			char *str_arithm = r_str_newf ("%s ARITHMETIC { %s }", str, arithm);
			sdb_set (db_aritm, key, str_arithm, 0);
			free (str_arithm);
			free (arithm);
		}
		if (arithm_ct) {
			char *str_arithm_ct = r_str_newf ("%s ARITHMETIC_CONST { %s }", str, arithm_ct);
			sdb_set (db_aritm_ct, key, str_arithm_ct, 0);
			free (str_arithm_ct);
			free (arithm_ct);
		}
	}

	free (str);
}
