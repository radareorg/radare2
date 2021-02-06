#include <r_types.h>
#include <r_util.h>
#include <r_anal.h>

/*	shared internal state of the subgraph generating functions	*/

typedef struct esil_cfg_generator_t {
	RAnalEsil *esil;
	union {
		RStack *ifelse;
		RStack *vals;
	};
	// union for semantic purposes
	RContRBTree *blocks;
	// consider moving this to cfg? well, yes and no.
	// making Graph nodes fast available in RAnalEsilCFG is great idea
	// A balanced tree is only best solution, if we want to store and lookup intervals
	// We need to look for intervals, so that we can resolve goto destinations INSIDE of a cpu-instruction
	// After an instruction got graphed, we only need their entry node (nodes with first == {xxx, 0 })
	// So after graphing an instruction, the blocks-tree should be cleared (don't free the content)
	// 	and nodes with first == {xxx, 0} should be stored in an sdb or similar in cfg, with xxx as key
	RAnalEsilCFG *cfg;
	RGraphNode *cur;
	// current graph-node, so that I don't have to abuse cfg->start
	RIDStorage *atoms;
	// is this needed
	ut64 off;
	// is this needed
} EsilCfgGen;

// esil has support for multiple elses,
// so we need these cookies on the ifelse-stack to keep track of things:
// when entering an if-block the parent is set as the else_block
// when entering an else block it is set as else_block, if is_else is false, other wise as if_block
// when entering an else block is_else flips
typedef struct esil_cfg_scope_cookie_t {
	RGraphNode *if_block;
	RGraphNode *else_block;
	bool is_else;
} EsilCfgScopeCookie;

typedef enum {
	ESIL_VAL_CONST,
	ESIL_VAL_REG,
	ESIL_VAL_RESULT
} EsilValType;

typedef struct esil_value_t {
	ut64 val; //should be a union, but for goto-analysis ut64 is fine
	EsilValType type;
} EsilVal;

/*	HELPERS 	*/

static char *condrets_strtok(char *str, const char tok) {
	if (!str) {
		return NULL;
	}
	ut32 i = 0;
	while (1 == 1) {
		if (!str[i]) {
			break;
		}
		if (str[i] == tok) {
			str[i] = '\0';
			return &str[i + 1];
		}
		i++;
	}
	return NULL;
}

RAnalEsilOp *esil_get_op (RAnalEsil *esil, const char *op) {
	r_return_val_if_fail (R_STR_ISNOTEMPTY (op) && esil && esil->ops, NULL);
	return ht_pp_find (esil->ops, op, NULL);
}

// this little thot atomizes an esil expressions by splitting it on ','
static void esil_expr_atomize(RIDStorage *atoms, char *expr) {
	ut32 forget_me;
	for (
		; !!expr && r_id_storage_add (atoms, expr, &forget_me);
		expr = condrets_strtok (expr, ',')) {
	}
}

static void _free_bb_cb(void *data) {
	RAnalEsilBB *bb = (RAnalEsilBB *)data;
	free (bb->expr);
	free (bb);
}

// REMINDER: generating the block content needs to prepend setting the program counter
// r_anal_esil_cfg_op does this ^, use it whenever generating cfg from op

// this nasty function is an insert-compare for RGraphNodes that contain RAnalEsilBB
static int _graphnode_esilbb_insert_cmp(void *incoming, void *in, void *user) {
	RGraphNode *incoming_gnode = (RGraphNode *)incoming;
	RGraphNode *in_gnode = (RGraphNode *)in;
	RAnalEsilBB *incoming_bb = (RAnalEsilBB *)incoming_gnode->data;
	RAnalEsilBB *in_bb = (RAnalEsilBB *)in_gnode->data;

	// RAnalEsilBBs have the nice property, that they cannot intersect,
	// so just comparing first and first should be fine for inserting
#if 0
	return incoming_bb->first - in_bb->first;
#endif
	// We MUST NOT use direct subtraction here, since st64 vs st32 can break the tree
	// be careful and check by compares
	if (incoming_bb->first.off < in_bb->first.off) {
		return -1;
	}
	if (incoming_bb->first.off > in_bb->first.off) {
		return 1;
	}
	// ok, so upper 64 msb are equal, now use the lower 16 lsb
	return incoming_bb->first.idx - in_bb->first.idx;
}

static int _graphnode_esilbb_find_cmp(void *incoming, void *in, void *user) {
	RAnalEsilEOffset *find_me = (RAnalEsilEOffset *)incoming;
	RGraphNode *in_gnode = (RGraphNode *)in;
	RAnalEsilBB *in_bb = (RAnalEsilBB *)in_gnode->data;
	// not sure if this is needed that way
	if (find_me->off < in_bb->first.off) {
		return -1;
	}
	if (find_me->off > in_bb->last.off) {
		return 1;
	}
	if (find_me->idx < in_bb->first.idx) {
		return -1;
	}
	if (find_me->idx > in_bb->last.idx) {
		return 1;
	}
	return 0;
}

static int _graphnode_delete_always_0_cmp(void *incoming, void *in, void *user) {
	EsilCfgGen *gen = (EsilCfgGen *)user;
	RGraphNode *delete_me = (RGraphNode *)in;
	RAnalEsilBB *delete_me_bb = (RAnalEsilBB *)delete_me->data;
	r_graph_del_node (gen->cfg->g, delete_me);
	ut32 id;
	for (id = delete_me_bb->first.idx; id <= delete_me_bb->last.idx; id++) {
		r_id_storage_delete (gen->atoms, id);
	}
	return 0;
}

void _handle_if_enter (EsilCfgGen *gen, ut32 id, const bool has_next) {
	if (!has_next) {
		return;
	}
	// TODO: check allocation here
	EsilCfgScopeCookie *cookie = R_NEW0 (EsilCfgScopeCookie);

	// get current bb
	//	RAnalEsilBB *bb = (RAnalEsilBB *)gen->cur->data;

	// create if-enter-bb
	RAnalEsilBB *entered_bb = R_NEW0 (RAnalEsilBB);
	entered_bb->first.off = entered_bb->last.off = gen->off;
	entered_bb->first.idx = entered_bb->last.idx = id + 1;
	entered_bb->enter = R_ANAL_ESIL_BLOCK_ENTER_TRUE;

	// create if-entered-graph-node
	RGraphNode *entered_node = r_graph_add_node (gen->cfg->g, entered_bb);
	entered_node->free = _free_bb_cb;
	r_rbtree_cont_insert (gen->blocks, entered_node, _graphnode_esilbb_insert_cmp, NULL);

	// add edge from entering node to entered node
	r_graph_add_edge (gen->cfg->g, gen->cur, entered_node);

	// push scope-cookie
	cookie->if_block = entered_node;
	cookie->else_block = gen->cur;
	r_stack_push (gen->ifelse, cookie);
	gen->cur = entered_node;
}

void _handle_else_enter (EsilCfgGen *gen, ut32 id, const bool has_next) {
	if (!has_next || r_stack_is_empty (gen->ifelse)) {
		// no cookie no todo
		return;
	}
	EsilCfgScopeCookie *cookie = (EsilCfgScopeCookie *)r_stack_peek (gen->ifelse);

	// create if-enter-bb
	RAnalEsilBB *entered_bb = R_NEW0 (RAnalEsilBB);
	entered_bb->first.off = entered_bb->last.off = gen->off;
	entered_bb->first.idx = entered_bb->last.idx = id + 1;

	// create if-entered-graph-node
	RGraphNode *entered_node = r_graph_add_node (gen->cfg->g, entered_bb);
	entered_node->free = _free_bb_cb;
	r_rbtree_cont_insert (gen->blocks, entered_node, _graphnode_esilbb_insert_cmp, NULL);

	if (cookie->is_else) {
		entered_bb->enter = R_ANAL_ESIL_BLOCK_ENTER_TRUE;
		r_graph_add_edge (gen->cfg->g, cookie->if_block, entered_node);
		cookie->if_block = entered_node;
		cookie->else_block = gen->cur;
		cookie->is_else = false;
	} else {
		entered_bb->enter = R_ANAL_ESIL_BLOCK_ENTER_FALSE;
		r_graph_add_edge (gen->cfg->g, cookie->else_block, entered_node);
		cookie->else_block = entered_node;
		cookie->if_block = gen->cur;
		cookie->is_else = true;
	}
	gen->cur = entered_node;
}

void _handle_fi_leave (EsilCfgGen *gen, ut32 id, const bool has_next) {
	EsilCfgScopeCookie *cookie = r_stack_pop (gen->ifelse);
	if (!cookie) {
		// no if, no fi todo
		return;
	}

	RAnalEsilBB *cur_bb = (RAnalEsilBB *)gen->cur->data;
	// this block is not executed when the if or else block is empty
	if (memcmp (&cur_bb->first, &cur_bb->last, sizeof (RAnalEsilEOffset))) {
		// TODO: add some thoughts in comments here
		cur_bb->last.idx--;
		RAnalEsilBB *leaving_bb = R_NEW0 (RAnalEsilBB);
		leaving_bb->first.off = leaving_bb->last.off = gen->off;
		leaving_bb->first.idx = leaving_bb->last.idx = id;
		RGraphNode *leaving_node = r_graph_add_node (gen->cfg->g, leaving_bb);
		leaving_node->free = _free_bb_cb;
		r_graph_add_edge (gen->cfg->g, gen->cur, leaving_node);
		r_rbtree_cont_insert (gen->blocks, leaving_node, _graphnode_esilbb_insert_cmp, NULL);
		gen->cur = leaving_node;
	}
	r_graph_add_edge (gen->cfg->g, cookie->is_else ? cookie->if_block : cookie->else_block, gen->cur);
	free (cookie);
}

// this function handles '?{','}{’ and '}'
// return type should probably be a bool, but idk
void _handle_control_flow_ifelsefi (EsilCfgGen *gen, char *atom, ut32 id) {
	// we're probably going to see more ?{ and }, than }{
	// so checking against ?{ and } befor }{ is therefor better for perf (lololol)
	if (!strcmp (atom, "?{")) {
		_handle_if_enter (gen, id, !!r_id_storage_get (gen->atoms, id + 1));
		return;
	}
	if (!strcmp (atom, "}")) {
		_handle_fi_leave (gen, id, !!r_id_storage_get (gen->atoms, id + 1));
		return;
	}
	if (!strcmp (atom, "}{")) {
		_handle_else_enter (gen, id, !!r_id_storage_get (gen->atoms, id + 1));
	}
}

// this little function is expected to generate a subgraph with most nodes in it
// but not all edges. It's expected to handle if, else and fi
bool _round_0_cb (void *user, void *data, ut32 id) {
	EsilCfgGen *gen = (EsilCfgGen *)user;
	char *atom = (char *)data;
	RAnalEsilBB *bb = (RAnalEsilBB *)gen->cur->data;
	RAnalEsilOp *op = esil_get_op (gen->esil, atom);
	bb->last.idx = (ut16)id;
	if (op && op->type == R_ANAL_ESIL_OP_TYPE_CONTROL_FLOW) {
		_handle_control_flow_ifelsefi (gen, atom, id);
	}
	return true;
}

RGraphNode *_common_break_goto (EsilCfgGen *gen, ut32 id) {
	RAnalEsilEOffset off = { gen->off, (ut16)id };
	RGraphNode *gnode = r_rbtree_cont_find (gen->blocks, &off, _graphnode_esilbb_find_cmp, NULL);
	RAnalEsilBB *bb = (RAnalEsilBB *)gnode->data;
	if (id != bb->last.idx) {
		RAnalEsilBB *next_bb = R_NEW0 (RAnalEsilBB);
		// split blocks
		next_bb->first.off = gen->off;
		next_bb->first.idx = id + 1;
		next_bb->last = bb->last;
		bb->last.idx = id;
		RGraphNode *next_gnode = r_graph_node_split_forward (gen->cfg->g, gnode, next_bb);
		// TODO: implement node_split in graph api
		r_rbtree_cont_insert (gen->blocks, next_gnode, _graphnode_esilbb_insert_cmp, NULL);
	} else {
		RListIter *iter, *ator;
		RGraphNode *node;
		// TODO: improve perf here
		r_list_foreach_safe (gnode->out_nodes, iter, ator, node) {
			r_graph_del_edge (gen->cfg->g, gnode, node);
		}
	}
	return gnode;
	// r_graph_add_edge(gen->cfg->g, gnode, gen->cfg->end);
}

void _handle_break (EsilCfgGen *gen, ut32 id) {
	r_graph_add_edge (gen->cfg->g, _common_break_goto (gen, id), gen->cfg->end);
}

void _handle_goto (EsilCfgGen *gen, ut32 idx) {
	RGraphNode *gnode = _common_break_goto (gen, idx);
	RAnalEsilBB *bb = (RAnalEsilBB *)gnode->data;
	// so what we're doing here is emulating this block with a certain degree of abstraction:
	// no reg-access
	// no io-access
	// stack-movents
	// maybe arithmetic stack operations
	//
	// we need to figure out the goto destination
	// ex: "a,b,=,12,GOTO" => goto dst is 12
	// ex: "42,a,4,+,b,=,GOTO" => goto dst is 42
	//
	// TODO: also handle "2,14,+,GOTO" in later versions
	ut16 id;
	// bb->last.idx is the GOTO operation itself, we do not reach this in the loop
	for (id = bb->first.idx; id < bb->last.idx; id++) {
		char *atom = (char *)r_id_storage_get (gen->atoms, (ut32)id);
		RAnalEsilOp *op = esil_get_op (gen->esil, atom);
		if (op) {
			ut32 j;
			for (j = 0; j < op->pop; j++) {
				free (r_stack_pop (gen->vals));
			}
			for (j = 0; j < op->push; j++) {
				EsilVal *val = R_NEW (EsilVal);
				val->type = ESIL_VAL_RESULT;
				r_stack_push (gen->vals, val);
			}
		} else {
			EsilVal *val = R_NEW (EsilVal);
			if (r_reg_get (gen->esil->anal->reg, atom, -1)) {
				val->type = ESIL_VAL_REG;
			} else {
				val->type = ESIL_VAL_CONST;
				val->val = r_num_get (NULL, atom);
			}
			r_stack_push (gen->vals, val);
		}
	}
	EsilVal *v = r_stack_pop (gen->vals);
	if (!v || v->type != ESIL_VAL_CONST) {
		free (v);
		eprintf ("Cannot resolve GOTO dst :(\n");
		goto beach;
	}

	// get the node to the corresponding GOTO destination
	RAnalEsilEOffset dst_off = { gen->off, (ut16)v->val };
	RGraphNode *dst_node = r_rbtree_cont_find (gen->blocks, &dst_off, _graphnode_esilbb_find_cmp, NULL);
	if (!dst_node) {
		// out-of-bounds
		// check if this works
		dst_node = gen->cfg->end;
	} else {
		RAnalEsilBB *dst_bb = (RAnalEsilBB *)dst_node->data;
		if (dst_bb->first.idx != v->val) {
			RAnalEsilBB *split_bb = R_NEW0 (RAnalEsilBB);
			split_bb[0] = dst_bb[0];
			dst_bb->last.idx = v->val - 1;
			split_bb->first.idx = v->val;
			RGraphNode *split = r_graph_node_split_forward (gen->cfg->g, dst_node, split_bb);
			r_graph_add_edge (gen->cfg->g, dst_node, split);
			dst_node = split;
		}
	}

	r_graph_add_edge (gen->cfg->g, gnode, dst_node);
beach:
	while (!r_stack_is_empty (gen->vals)) {
		free (r_stack_pop (gen->vals));
	}
}

bool _round_1_cb (void *user, void *data, ut32 id) {
	EsilCfgGen *gen = (EsilCfgGen *)user;
	char *atom = (char *)data;
	RAnalEsilOp *op = esil_get_op (gen->esil, atom);
	if (op && op->type == R_ANAL_ESIL_OP_TYPE_CONTROL_FLOW) {
		if (!strcmp ("BREAK", atom)) {
			_handle_break (gen, id);
		}
		if (!strcmp ("GOTO", atom)) {
			_handle_goto (gen, id);
		}
	}
	return true;
}

void _round_2_cb (RGraphNode *n, RGraphVisitor *vi) {
	RAnalEsilBB *bb = (RAnalEsilBB *)n->data;
	EsilCfgGen *gen = (EsilCfgGen *)vi->data;
	RStrBuf *buf = r_strbuf_new ((char *)r_id_storage_get (gen->atoms, bb->first.idx));
	r_strbuf_append (buf, ",");
	ut32 id;
	for (id = bb->first.idx + 1; id <= bb->last.idx; id++) {
		// use r_id_storage_take here to start fini for the atoms
		r_strbuf_appendf (buf, "%s,", (char *)r_id_storage_take (gen->atoms, id));
	}
	bb->expr = strdup (r_strbuf_get (buf));
	r_strbuf_free (buf);
	r_rbtree_cont_delete (gen->blocks, n, _graphnode_esilbb_insert_cmp, NULL);
}

// this function takes a cfg, an offset and an esil expression
// concatinates to already existing graph.
// Also expects RIDStorage atoms and RContRBTree to be allocate in prior of the call
static RAnalEsilCFG *esil_cfg_gen(RAnalEsilCFG *cfg, RAnal *anal, RIDStorage *atoms, RContRBTree *blocks, RStack *stack, ut64 off, char *expr) {
	// consider expr as RStrBuf, so that we can sanitze broken esil
	// (ex: "b,a,+=,$z,zf,:=,7,$c,cf,:=,zf,?{,1,b,+=,cf,?{,3,a,-=" =>
	// 	"b,a,+=,$z,zf,:=,7,$c,cf,:=,zf,?{,1,b,+=,cf,?{,3,a,-=,},}")

	// allocate some stuff
	char *_expr = strdup (expr);
	if (!_expr) {
		return cfg; //NULL?
	}
	RAnalEsilBB *end_bb = R_NEW0 (RAnalEsilBB);
	if (!end_bb) {
		free (_expr);
		return cfg;
	}
	RGraphNode *start, *end = r_graph_add_node (cfg->g, end_bb);
	if (!end) {
		free (end_bb);
		free (_expr);
		return cfg;
	}
	end->free = _free_bb_cb;

	esil_expr_atomize (atoms, _expr);

	// previous expression's post-dominator is the current expression starting point
	//
	// MUST NOT use cfg->start as starting point of subgraph,
	// since it marks the start of the whole graph
	//
	// cpu-instruction starts at this node
	//
	// without information about the outside cfg, we CANNOT merge cpu-instructions

	RAnalEsilBB *bb = (RAnalEsilBB *)cfg->end->data;

	end_bb->expr = bb->expr;
	// FIXME: use end_bb here
	bb->expr = NULL;
	bb->first.off = bb->last.off = off;
	bb->first.idx = bb->last.idx = 0;
	start = cfg->end;

	EsilCfgGen gen = { anal->esil, { stack }, blocks, cfg, start, atoms, off };
	cfg->end = end;
	// create an edge from cur to end?
	// Well yes, but no. Would be great to do this,
	// but rgraph api is slow af on node delition. Be careful instead

	// We created a new graph node above, which is going to be the post-dominator
	// of the subgraph, that we are going to add to the existing graph.
	// The post-dominator of the previous added subgraph is the starting node here.
	// We add this to the block-tree
	r_rbtree_cont_insert (blocks, gen.cur, _graphnode_esilbb_insert_cmp, NULL);

	// end of the initial setup, next generate blocks and insert them in the tree

	// round 0 adds a subgraph from if, else and fi
	r_id_storage_foreach (atoms, _round_0_cb, &gen);
	// make cfg->end effective post-dominator
	r_graph_add_edge (cfg->g, gen.cur, cfg->end);
	{
		// stack unwinding
		EsilCfgScopeCookie *cookie;
		while ((cookie = r_stack_pop (stack))) {
			r_graph_add_edge (cfg->g,
				cookie->is_else ? cookie->if_block : cookie->else_block, cfg->end);
			free (cookie);
		}
	}

	// next do round 1: split blocks from GOTOs and BREAKs
	r_id_storage_foreach (atoms, _round_1_cb, &gen);

	// next do dfs:
	//  - remove each node from blocks-tree, that can be reached by a dfs path
	//  - when removing a node from block-tree, synthesize node->bb->expr with RStrBuf
	{
		// dfs walk removes used atoms
		RGraphVisitor vi = { _round_2_cb, NULL, NULL, NULL, NULL, &gen };
		r_graph_dfs_node (cfg->g, start, &vi);
	}
	// this loop removes unused atoms
	do {
	} while (blocks->root && r_rbtree_cont_delete (blocks, NULL, _graphnode_delete_always_0_cmp, &gen));

	free (_expr);
	return cfg;
}

R_API RAnalEsilCFG *r_anal_esil_cfg_new(void) {
	RAnalEsilCFG *cf = R_NEW0 (RAnalEsilCFG);
	if (cf) {
		RAnalEsilBB *p = R_NEW0 (RAnalEsilBB);
		if (!p) {
			free (cf);
			return NULL;
		}
		p->expr = strdup ("end");
		if (!p->expr) {
			free (p);
			free (cf);
			return NULL;
		}
		cf->g = r_graph_new ();
		if (!cf->g) {
			free (p->expr);
			free (p);
			free (cf);
			return NULL;
		}
		cf->start = cf->end = r_graph_add_node (cf->g, p);
		// end node is always needed as post-dominator
		// idea here is to split the initial one node graph in the node
		if (!cf->end) {
			free (p->expr);
			free (p);
			r_graph_free (cf->g);
			free (cf);
			return NULL;
		}
		if (cf->g->nodes) {
			cf->end->free = _free_bb_cb;
		}
	}
	return cf;
}

// this little function takes a cfg, an offset and an esil expression
// concatinates to already existing graph
R_API RAnalEsilCFG *r_anal_esil_cfg_expr(RAnalEsilCFG *cfg, RAnal *anal, const ut64 off, char *expr) {
	if (!anal || !anal->esil) {
		return NULL;
	}
	RStack *stack = r_stack_new (4);
	if (!stack) {
		return NULL;
	}
	RContRBTree *blocks = r_rbtree_cont_new ();
	if (!blocks) {
		r_stack_free (stack);
		return NULL;
	}
	RIDStorage *atoms = r_id_storage_new (0, 0xfffe);
	if (!atoms) {
		r_stack_free (stack);
		r_rbtree_cont_free (blocks);
		return NULL;
	}
	RAnalEsilCFG *cf = cfg ? cfg : r_anal_esil_cfg_new ();
	if (!cf) {
		r_stack_free (stack);
		r_id_storage_free (atoms);
		r_rbtree_cont_free (blocks);
		return NULL;
	}
	RAnalEsilCFG *ret = esil_cfg_gen (cf, anal, atoms, blocks, stack, off, expr);
	r_stack_free (stack);
	r_id_storage_free (atoms);
	r_rbtree_cont_free (blocks);
	return ret;
}

R_API RAnalEsilCFG *r_anal_esil_cfg_op(RAnalEsilCFG *cfg, RAnal *anal, RAnalOp *op) {
	if (!op || !anal || !anal->reg || !anal->esil) {
		return NULL;
	}
	RAnalEsilBB *glue_bb = R_NEW0 (RAnalEsilBB);
	if (!glue_bb) {
		eprintf ("Couldn't allocate glue_bb\n");
		return NULL;
	}
	RStrBuf *glue = r_strbuf_new ("");
	if (!glue) {
		free (glue_bb);
		eprintf ("Couldn't allocate glue\n");
		return NULL;
	}
	const char *pc = r_reg_get_name (anal->reg, R_REG_NAME_PC);
	r_strbuf_setf (glue, "0x%" PFMT64x ",%s,:=,", op->addr + op->size, pc);
	glue_bb->expr = strdup (r_strbuf_get (glue));
	r_strbuf_free (glue);
	if (!glue_bb->expr) {
		free (glue_bb);
		eprintf ("Couldn't strdup\n");
		return NULL;
	}
	glue_bb->enter = R_ANAL_ESIL_BLOCK_ENTER_GLUE;
	glue_bb->first.off = glue_bb->last.off = op->addr;
	glue_bb->first.idx = glue_bb->last.idx = 0;

	RAnalEsilCFG *ret;

	if (!cfg) {
		ret = r_anal_esil_cfg_expr (cfg, anal, op->addr, r_strbuf_get (&op->esil));
		RGraphNode *glue_node = r_graph_add_node (ret->g, glue_bb);
		glue_node->free = _free_bb_cb;
		r_graph_add_edge (ret->g, glue_node, ret->start);
		ret->start = glue_node;
	} else {
		RGraphNode *glue_node = r_graph_add_node (cfg->g, glue_bb);
		glue_node->free = _free_bb_cb;
		r_graph_add_edge (cfg->g, cfg->end, glue_node);
		void *foo = cfg->end->data;
		cfg->end->data = glue_node->data;
		glue_node->data = foo;
		cfg->end = glue_node;
		ret = r_anal_esil_cfg_expr (cfg, anal, op->addr, r_strbuf_get (&op->esil));
	}
	return ret;
}

static void merge_2_blocks(RAnalEsilCFG *cfg, RGraphNode *node, RGraphNode *block) {
	// merge node and block, block dies in this
	// block----->node ===> node
	if (node == cfg->end) {
		// do not merge the post-dominator
		return;
	}
	RListIter *iter;
	RGraphNode *n;
	r_list_foreach (block->in_nodes, iter, n) {
		r_graph_add_edge (cfg->g, n, node);
	}
	RAnalEsilBB *block_bb, *node_bb = (RAnalEsilBB *)node->data;
	block_bb = (RAnalEsilBB *)block->data;
	if ((block_bb->enter == R_ANAL_ESIL_BLOCK_ENTER_TRUE) || (block_bb->enter == R_ANAL_ESIL_BLOCK_ENTER_FALSE)) {
		node_bb->enter = block_bb->enter;
	} else {
		node_bb->enter = R_ANAL_ESIL_BLOCK_ENTER_NORMAL;
	}
	RStrBuf *buf = r_strbuf_new (block_bb->expr);
	node_bb->first = block_bb->first;
	r_graph_del_node (cfg->g, block);
	r_strbuf_appendf (buf, "\n%s", node_bb->expr);
	free (node_bb->expr);
	node_bb->expr = strdup (r_strbuf_get (buf));
	if (block == cfg->start) {
		cfg->start = node;
	}
}

// this shit is slow af, bc of foolish graph api
R_API void r_anal_esil_cfg_merge_blocks(RAnalEsilCFG *cfg) {
	if (!cfg || !cfg->g || !cfg->g->nodes) {
		return;
	}
	RListIter *iter, *ator;
	RGraphNode *node;
	r_list_foreach_safe (cfg->g->nodes, iter, ator, node) {
		if (r_list_length (node->in_nodes) == 1) {
			RAnalEsilBB *bb = (RAnalEsilBB *)node->data;
			RGraphNode *top = (RGraphNode *)r_list_get_top (node->out_nodes);
			// segfaults here ?
			if (!(top && bb->enter == R_ANAL_ESIL_BLOCK_ENTER_GLUE && (r_list_length (top->in_nodes) > 1))) {
				RGraphNode *block = (RGraphNode *)r_list_get_top (node->in_nodes);
				if (r_list_length (block->out_nodes) == 1) {
					merge_2_blocks (cfg, node, block);
				}
			}
		}
	}
}

R_API void r_anal_esil_cfg_free(RAnalEsilCFG *cfg) {
	if (cfg && cfg->g) {
		r_graph_free (cfg->g);
	}
	free (cfg);
}
