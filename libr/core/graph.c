/* Copyright radare2 2014-2015 - Author: pancake */

#include <r_core.h>
static const char *mousemodes[] = { "canvas-y", "canvas-x", "node-y", "node-x", NULL };
static int mousemode = 0;

#define BORDER 3
#define BORDER_WIDTH 4
#define BORDER_HEIGHT 3
#define MARGIN_TEXT_X 2
#define MARGIN_TEXT_Y 2
#define MAX_NODE_WIDTH 18

#define OS_SIZE 128
struct ostack {
	int nodes[OS_SIZE];
	int size;
};

typedef struct {
	int x;
	int y;
	int w;
	int h;
	ut64 addr;
	int depth;
	char *text;
} Node;

typedef struct {
	int nth;
	int from;
	int to;
} Edge;

struct graph {
	RCore *core;
	RConsCanvas *can;
	RAnalFunction *fcn;
	Node *nodes;
	Edge *edges;
	int n_nodes;
	int n_edges;
	int is_callgraph;
	int is_instep;
	int is_simple_mode;
	int is_small_nodes;

	unsigned int curnode;

	struct ostack ostack;
	int need_reload_nodes;
	int need_update_seek;
	int update_seek_on;
	int force_update_seek;
};

#if 0
static Node nodes[] = {
	 {25,4, 18, 6, 0x8048320, "push ebp\nmov esp, ebp\njz 0x8048332" },
	 {10,13, 18, 5, 0x8048332, "xor eax, eax\nint 0x80\n"},
	 {30,13, 18, 5, 0x8048324, "pop ebp\nret"},
	{NULL}
};

static Edge edges[] = {
	{ 0, 0, 1 },
	{ 1, 0, 2 },
	{ -1 }
};
#endif

#define G(x,y) r_cons_canvas_gotoxy (g->can, x, y)
#define W(x) r_cons_canvas_write (g->can, x)
#define B(x,y,w,h) r_cons_canvas_box(g->can, x,y,w,h,NULL)
#define B1(x,y,w,h) r_cons_canvas_box(g->can, x,y,w,h,Color_BLUE)
#define B2(x,y,w,h) r_cons_canvas_box(g->can, x,y,w,h,Color_MAGENTA)
#define L(x,y,x2,y2) r_cons_canvas_line(g->can, x,y,x2,y2,0)
#define L1(x,y,x2,y2) r_cons_canvas_line(g->can, x,y,x2,y2,1)
#define L2(x,y,x2,y2) r_cons_canvas_line(g->can, x,y,x2,y2,2)
#define F(x,y,x2,y2,c) r_cons_canvas_fill(g->can, x,y,x2,y2,c,0)

static void ostack_init(struct ostack *os) {
	os->size = 0;
	os->nodes[0] = 0;
}

static void ostack_push(struct ostack *os, int el) {
	if (os->size < OS_SIZE - 1)
		os->nodes[++os->size] = el;
}

static int ostack_pop(struct ostack *os) {
	return os->size > 0 ? os->nodes[--os->size] : 0;
}

static void update_node_dimension(Node nodes[], int nodes_size, int is_small) {
	int i;
	for (i = 0; i < nodes_size; ++i) {
		Node *n = &nodes[i];
		if (is_small) {
			n->w = n->h = 0;
		} else {
			n->w = r_str_bounds (n->text, &n->h);
			n->w += BORDER_WIDTH;
			n->h += BORDER_HEIGHT;
			n->w = R_MAX (MAX_NODE_WIDTH, n->w);
		}
	}
}

static void small_Node_print(struct graph *g, Node *n, int cur) {
	char title[128];

	if (!G (n->x + 2, n->y - 1))
		return;
	if (cur) {
		W("[_@@_]");
		(void)G (-g->can->sx, -g->can->sy + 2);
		snprintf (title, sizeof (title) - 1,
				"0x%08"PFMT64x":", n->addr);
		W (title);
		(void)G (-g->can->sx, -g->can->sy + 3);
		W (n->text);
	} else {
		W("[____]");
	}
	return;
}

static void normal_Node_print(struct graph *g, Node *n, int cur) {
	char title[128];
	char *text;
	int delta_x = 0;
	int delta_y = 0;
	int x, y;

#if SHOW_OUT_OF_SCREEN_NODES
	x = n->x + g->can->sx;
	y = n->y + n->h + g->can->sy;
	if (x < 0 || x > g->can->w)
		return;
	if (y < 0 || y > g->can->h)
		return;
#endif
	x = n->x + g->can->sx;
	y = n->y + g->can->sy;
	if (x < -MARGIN_TEXT_X)
		delta_x = -x - MARGIN_TEXT_X;
	if (x + n->w < -MARGIN_TEXT_X)
		return;
	if (y < -1)
		delta_y = -y - MARGIN_TEXT_Y;

	if (cur) {
		//F (n->x,n->y, n->w, n->h, '.');
		snprintf (title, sizeof (title)-1,
				"-[ 0x%08"PFMT64x" ]-", n->addr);
	} else {
		snprintf (title, sizeof (title)-1,
				"   0x%08"PFMT64x"   ", n->addr);
	}
	if (delta_x < strlen(title) && G(n->x + MARGIN_TEXT_X + delta_x, n->y + 1))
		W(title + delta_x);

	if (G(n->x + MARGIN_TEXT_X + delta_x, n->y + MARGIN_TEXT_Y + delta_y)) {
		text = r_str_crop (n->text, delta_x, delta_y, n->w - BORDER_WIDTH, n->h);
		if (text) {
			W (text);
			free (text);
		} else {
			W (n->text);
		}
	}

	// TODO: check if node is traced or not and hsow proper color
	// This info must be stored inside Node* from RCore*
	if (cur) {
		B1 (n->x, n->y, n->w, n->h);
	} else {
		B (n->x, n->y, n->w, n->h);
	}
}

static Node *get_current_node(struct graph *g) {
	 return &g->nodes[g->curnode];
}

static int count_exit_edges(struct graph *g, int n) {
	int i, count = 0;
	for (i = 0; i < g->n_edges; i++) {
		if (g->edges[i].from == n) {
			count++;
		}
	}
	return count;
}

static int find_edge_node(struct graph *g, int cur, int nth) {
	if (g->edges) {
		int i;
		for (i = 0; i < g->n_edges; i++) {
			if (g->edges[i].from == cur && g->edges[i].nth == nth)
				return g->edges[i].to;
		}
	}
	return -1;
}

static int find_node_idx(struct graph *g, ut64 addr) {
	if (g->nodes) {
		int i;
		for (i = 0; i < g->n_nodes; i++) {
			if (g->nodes[i].addr == addr)
				return i;
		}
	}
	return -1;
}

static void set_layout_bb_depth(struct graph *g, int nth, int depth) {
	int j, f, old_d;
	if (nth >= g->n_nodes)
		return;

	old_d = g->nodes[nth].depth;
	g->nodes[nth].depth = depth;
	if (old_d != -1)
		return;

	j = find_edge_node (g, nth, 0);
	if (j != -1)
		set_layout_bb_depth (g, j, depth + 1);
	f = find_edge_node (g, nth, 1);
	if (f != -1)
		set_layout_bb_depth (g, f, depth + 1);
	// TODO: support more than two destination points (switch tables?)
}

static void set_layout_bb(struct graph *g) {
	int i, j, rh, nx;
	int *rowheight = NULL;
	int maxdepth = 0;
	const int h_spacing = 12;
	const int v_spacing = 4;

	set_layout_bb_depth (g, 0, 0);

	// identify max depth
	for (i = 0; i < g->n_nodes; i++) {
		if (g->nodes[i].depth > maxdepth)
			maxdepth = g->nodes[i].depth;
	}
	// identify row height
	rowheight = malloc (sizeof (int) * maxdepth);
	for (i = 0; i < maxdepth; i++) {
		rh = 0;
		for (j = 0; j < g->n_nodes; j++) {
			if (g->nodes[j].depth == i)
				if (g->nodes[j].h > rh)
					rh = g->nodes[j].h;
		}
		rowheight[i] = rh;
	}

	// vertical align // depe
	for (i = 0; i < g->n_nodes; i++) {
		g->nodes[i].y = 1;
		for (j = 0; j < g->nodes[i].depth; j++)
			g->nodes[i].y += rowheight[j] + v_spacing;
	}
	// horitzontal align
	for (i = 0; i < maxdepth; i++) {
		nx = (i % 2) * 10;
		for (j = 0; j < g->n_nodes; j++) {
			if (g->nodes[j].depth == i) {
				g->nodes[j].x = nx;
				nx += g->nodes[j].w + h_spacing;
			}
		}
	}
	free (rowheight);
}

static void set_layout_callgraph(struct graph *g) {
	int y = 5, x = 20;
	int i;

	for (i = 0; i < g->n_nodes; i++) {
		// wrap to width 'w'
		if (i > 0) {
			if (g->nodes[i].x < g->nodes[i-1].x) {
				y += 10;
				x = 0;
			}
		}
		g->nodes[i].x = x;
		g->nodes[i].y = i? y: 2;
		x += 30;
	}
}

static int get_bbnodes(struct graph *g) {
	RAnalBlock *bb;
	RListIter *iter;
	Node *nodes;
	int i;

	nodes = calloc(r_list_length (g->fcn->bbs), sizeof(Node));
	if (!nodes)
		return R_FALSE;

	i = 0;
	r_list_foreach (g->fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX)
			continue;

		if (g->is_simple_mode) {
			nodes[i].text = r_core_cmd_strf (g->core,
					"pI %d @ 0x%08"PFMT64x, bb->size, bb->addr);
		}else {
			nodes[i].text = r_core_cmd_strf (g->core,
					"pDi %d @ 0x%08"PFMT64x, bb->size, bb->addr);
		}
		nodes[i].addr = bb->addr;
		nodes[i].depth = -1;
		nodes[i].x = 0;
		nodes[i].y = 0;
		nodes[i].w = 0;
		nodes[i].h = 0;
		i++;
	}

	if (g->nodes)
		free(g->nodes);
	g->nodes = nodes;
	g->n_nodes = i;
	return R_TRUE;
}

static int get_cgnodes(struct graph *g) {
	int i = 0;
#if FCN_OLD
	int j;
	char *code;
	RAnalRef *ref;
	RListIter *iter;
	Node *nodes;

	int fcn_refs_length = r_list_length (g->fcn->refs);
	nodes = calloc (fcn_refs_length + 2, sizeof(Node));
	if (!nodes)
		return R_FALSE;

	nodes[i].text = strdup ("");
	nodes[i].addr = g->fcn->addr;
	nodes[i].depth = -1;
	nodes[i].x = 10;
	nodes[i].y = 3;
	nodes[i].w = 0;
	nodes[i].h = 0;
	i++;

	r_list_foreach (g->fcn->refs, iter, ref) {
		/* XXX: something is broken, why there are duplicated
		 *      nodes here?! goto check fcn->refs!! */
		/* avoid dups wtf */
		for (j = 0; j < i; j++) {
			if (ref->addr == nodes[j].addr)
				continue;
		}
		RFlagItem *fi = r_flag_get_at (g->core->flags, ref->addr);
		if (fi) {
			nodes[i].text = strdup (fi->name);
			nodes[i].text = r_str_concat (nodes[i].text, ":\n");
		} else {
			nodes[i].text = strdup ("");
		}
		code = r_core_cmd_strf (g->core,
			"pi 4 @ 0x%08"PFMT64x, ref->addr);
		nodes[i].text = r_str_concat (nodes[i].text, code);
		free (code);
		nodes[i].text = r_str_concat (nodes[i].text, "...\n");
		nodes[i].addr = ref->addr;
		nodes[i].depth = -1;
		nodes[i].x = 10;
		nodes[i].y = 10;
		nodes[i].w = 0;
		nodes[i].h = 0;
		i++;
	}

	if (g->nodes)
		free(g->nodes);
	g->nodes = nodes;
	g->n_nodes = i;
#else
	eprintf ("Must be sdbized\n");
#endif

	return R_TRUE;
}

static int get_bbedges(struct graph *g) {
	Edge *edges = NULL;
	RListIter *iter;
	RAnalBlock *bb;
	int i, n_edges;

	n_edges = 0;
	r_list_foreach (g->fcn->bbs, iter, bb) {
		if (bb->jump != UT64_MAX)
			n_edges++;
		if (bb->fail != UT64_MAX)
			n_edges++;
	}

	edges = calloc(n_edges, sizeof(Edge));
	if (!edges && n_edges != 0)
		return R_FALSE;

	i = 0;
	r_list_foreach (g->fcn->bbs, iter, bb) {
		// add edge from bb->addr to bb->jump / bb->fail
		if (bb->jump != UT64_MAX) {
			edges[i].nth = 0;
			edges[i].from = find_node_idx (g, bb->addr);
			edges[i].to = find_node_idx (g, bb->jump);
			i++;
		}
		if (bb->fail != UT64_MAX) {
			edges[i].nth = 1;
			edges[i].from = find_node_idx (g, bb->addr);
			edges[i].to = find_node_idx (g, bb->fail);
			i++;
		}
	}

	if (g->edges)
		free(g->edges);
	g->edges = edges;
	g->n_edges = i;
	return R_TRUE;
}

static int get_cgedges(struct graph *g) {
	int i = 0;
#if FCN_OLD
	Edge *edges = NULL;
	RAnalRef *ref;
	RListIter *iter;
	int refs_length;

	refs_length = r_list_length(g->fcn->refs);
	edges = calloc(refs_length, sizeof(Edge));
	if (!edges && refs_length != 0)
		return R_FALSE;

	r_list_foreach (g->fcn->refs, iter, ref) {
		edges[i].nth = 0;
		edges[i].from = find_node_idx (g, g->fcn->addr);
		edges[i].to = find_node_idx (g, ref->addr);
		i++;
	}

	if (g->edges)
		free(g->edges);
	g->edges = edges;
	g->n_edges = i;
#else
	#warning cgEdges not sdbized for fcn refs
#endif

	return R_TRUE;
}

static int reload_nodes(struct graph *g) {
	int ret;

	if (g->is_callgraph) {
		ret = get_cgnodes(g);
		if (!ret)
			return R_FALSE;
		ret = get_cgedges(g);
		if (!ret)
			return R_FALSE;
	} else {
		ret = get_bbnodes(g);
		if (!ret)
			return R_FALSE;

		ret = get_bbedges(g);
		if (!ret)
			return R_FALSE;
	}

	update_node_dimension(g->nodes, g->n_nodes, g->is_small_nodes);
	return R_TRUE;
}

static void update_seek(RConsCanvas *can, Node *n, int force) {
	int x, y, w, h;
	int doscroll = R_FALSE;

	if (!n) return;

	x = n->x + can->sx;
	y = n->y + can->sy;
	w = can->w;
	h = can->h;

	doscroll = force || y < 0 || y + 5 > h || x + 5 > w || x + n->w + 5 < 0;

	if (doscroll) {
		// top-left
		can->sy = -n->y + BORDER;
		can->sx = -n->x + BORDER;
		// center
		can->sy = -n->y + BORDER + (h / 8);
		can->sx = -n->x + BORDER + (w / 4);
	}
}

static void graph_set_layout(struct graph *g) {
	if (g->is_callgraph)
		set_layout_callgraph(g);
	else
		set_layout_bb(g);
}

static void graph_update_seek(struct graph *g, int node_index, int force) {
	g->need_update_seek = R_TRUE;
	g->update_seek_on = node_index;
	g->force_update_seek = force;
}

static void graph_free(struct graph *g) {
	if (g->nodes)
		free(g->nodes);
	if (g->edges)
		free(g->edges);
	free(g);
}

static void graph_print_node(struct graph *g, Node *n) {
	int cur = get_current_node(g) == n;

	if (g->is_small_nodes)
		small_Node_print(g, n, cur);
	else
		normal_Node_print(g, n, cur);
}

static void graph_print_nodes(struct graph *g) {
	int i;
	for (i = 0; i < g->n_nodes; ++i)
		if (i != g->curnode)
			graph_print_node(g, &g->nodes[i]);

	/* draw current node now to make it appear on top */
	graph_print_node (g, &g->nodes[g->curnode]);
}

static void graph_print_edge(struct graph *g, Node *a, Node *b, int nth) {
	int x, y, x2, y2;
	int xinc = 3 + 2 * (nth + 1);
	x = a->x + xinc;
	y = a->y + a->h;
	x2 = b->x + xinc;
	y2 = b->y;
	if (a == b) {
		x2 = a->x;
		y2 = y - 3;
	}
	switch (nth) {
	case 0: L1 (x, y, x2, y2); break;
	case 1: L2 (x, y, x2, y2); break;
	case -1: L (x, y, x2, y2); break;
	}
}

static void graph_print_edges(struct graph *g) {
	int i;
	if (g->edges) {
		for (i = 0; i < g->n_edges; i++) {
			if (g->edges[i].from == -1 || g->edges[i].to == -1)
				continue;

			Node *a = &g->nodes[g->edges[i].from];
			Node *b = &g->nodes[g->edges[i].to];
			int nth = g->edges[i].nth;
			if (count_exit_edges(g, g->edges[i].from) == 1)
				nth = -1; // blue line

			graph_print_edge (g, a, b, nth);
		}
	}
}

static void graph_toggle_small_nodes(struct graph *g) {
	g->is_small_nodes = !g->is_small_nodes;
	g->need_reload_nodes = R_TRUE;
}

static void graph_toggle_simple_mode(struct graph *g) {
	g->is_simple_mode = !g->is_simple_mode;
	g->need_reload_nodes = R_TRUE;
}

static void graph_toggle_callgraph(struct graph *g) {
	g->is_callgraph = !g->is_callgraph;
	g->need_reload_nodes = R_TRUE;
}

static int graph_reload_nodes(struct graph *g) {
	int ret;

	ret = reload_nodes(g);
	if (!ret)
		return R_FALSE;
	graph_set_layout(g);
	return R_TRUE;
}

static void follow_nth(struct graph *g, int nth) {
	int cn = find_edge_node (g, g->curnode, nth);
	if (cn != -1) {
		g->curnode = cn;
		ostack_push (&g->ostack, cn);
	}
}

static void graph_follow_true(struct graph *g) {
	follow_nth(g, 0);
	graph_update_seek(g, g->curnode, R_FALSE);
}

static void graph_follow_false(struct graph *g) {
	follow_nth(g, 1);
	graph_update_seek(g, g->curnode, R_FALSE);
}

static void graph_undo_node(struct graph *g) {
	g->curnode = ostack_pop(&g->ostack);
	graph_update_seek (g, g->curnode, R_FALSE);
}

static void graph_next_node(struct graph *g) {
	g->curnode = (g->curnode + 1) % g->n_nodes;
	ostack_push (&g->ostack, g->curnode);
	graph_update_seek (g, g->curnode, R_FALSE);
}

static void graph_prev_node(struct graph *g) {
	if (g->curnode == 0)
		g->curnode = g->n_nodes - 1;
	else
		g->curnode = g->curnode - 1;
	ostack_push (&g->ostack, g->curnode);
	graph_update_seek (g, g->curnode, R_FALSE);
}

static int graph_refresh(struct graph *g) {
	char title[128];
	int h, w = r_cons_get_size (&h);
	int ret;

	if (g->is_instep && g->core->io->debug) {
		RAnalFunction *f;
		r_core_cmd0 (g->core, "sr pc");
		f = r_anal_get_fcn_in (g->core->anal, g->core->offset, 0);
		if (f && f != g->fcn) {
			g->fcn = f;
			g->need_reload_nodes = R_TRUE;
		}
	}

	/* look for any change in the state of the graph
	 * and update what's necessary */
	if (g->need_reload_nodes) {
		ret = graph_reload_nodes(g);
		if (!ret)
			return R_FALSE;

		g->need_reload_nodes = R_FALSE;
	}
	if (g->need_update_seek) {
		update_seek(g->can, &g->nodes[g->update_seek_on], g->force_update_seek);
		g->need_update_seek = R_FALSE;
		g->update_seek_on = 0;
		g->force_update_seek = R_FALSE;
	}

	r_cons_clear00 ();

	r_cons_canvas_resize (g->can, w, h);
	r_cons_canvas_clear (g->can);

	graph_print_edges(g);
	graph_print_nodes(g);

	(void)G (-g->can->sx, -g->can->sy);
	snprintf (title, sizeof (title)-1,
		"[0x%08"PFMT64x"]> %d VV @ %s (nodes %d edges %d) %s mouse:%s",
		g->fcn->addr, g->ostack.size, g->fcn->name,
		g->n_nodes, g->n_edges, g->is_callgraph?"CG":"BB",
		mousemodes[mousemode]);
	W (title);

	r_cons_canvas_print (g->can);
	const char *cmdv = r_config_get (g->core->config, "cmd.gprompt");
	if (cmdv && *cmdv) {
		r_cons_gotoxy (0,1);
		r_core_cmd0 (g->core, cmdv);
	}
	r_cons_flush_nonewline ();
	return R_TRUE;
}

static void graph_init(struct graph *g) {
	g->nodes = NULL;
	g->edges = NULL;

	g->is_callgraph = R_FALSE;
	g->is_instep = R_FALSE;
	g->is_simple_mode = R_TRUE;
	g->is_small_nodes = R_FALSE;
	g->need_reload_nodes = R_TRUE;
	g->curnode = 0;
	g->need_update_seek = R_TRUE;
	g->update_seek_on = g->curnode;
	g->force_update_seek = R_TRUE;

	ostack_init(&g->ostack);
}

static struct graph *graph_new(RCore *core, RConsCanvas *can, RAnalFunction *fcn) {
	struct graph *g;

	g = (struct graph *)malloc(sizeof(struct graph));
	if (!g)
		return NULL;

	g->core = core;
	g->can = can;
	g->fcn = fcn;

	graph_init(g);
	return g;
}

R_API int r_core_visual_graph(RCore *core, RAnalFunction *_fcn) {
	RAnalFunction *fcn;
	RConsCanvas *can;
	struct graph *g;
	int ret;
	int wheelspeed;
	int okey, key, wheel;
	int w, h;
	int exit_graph = R_FALSE, is_error = R_FALSE;

	fcn = _fcn? _fcn: r_anal_get_fcn_in (core->anal, core->offset, 0);
	if (!fcn) {
		eprintf ("No function in current seek\n");
		return R_FALSE;
	}
	w = r_cons_get_size (&h);
	can = r_cons_canvas_new (w - 1, h - 1);
	if (!can) {
		eprintf ("Cannot create RCons.canvas context\n");
		return R_FALSE;
	}
	can->linemode = 1;
	can->color = r_config_get_i (core->config, "scr.color");
	// disable colors in disasm because canvas doesnt supports ansi text yet
	r_config_set_i (core->config, "scr.color", 0);

	g = graph_new(core, can, fcn);
	if (!g) {
		is_error = R_TRUE;
		goto err_graph_new;
	}

	core->cons->event_data = g;
	core->cons->event_resize = (RConsEvent)graph_refresh;

	while (!exit_graph && !is_error) {
		w = r_cons_get_size (&h);
		ret = graph_refresh(g);
		if (!ret) {
			is_error = R_TRUE;
			break;
		}

		r_cons_show_cursor(R_FALSE);
		wheel = r_config_get_i (core->config, "scr.wheel");
		if (wheel)
			r_cons_enable_mouse (R_TRUE);

		// r_core_graph_inputhandle()
		okey = r_cons_readchar ();
		key = r_cons_arrow_to_hjkl (okey);
		if (r_cons_singleton()->mouse_event) {
			wheelspeed = r_config_get_i (core->config, "scr.wheelspeed");
		} else {
			wheelspeed = 1;
		}

		switch (key) {
			case '=':
			case '|':
				{ // TODO: edit
					const char *buf = NULL;
					const char *cmd = r_config_get (core->config, "cmd.gprompt");
					r_line_set_prompt ("cmd.gprompt> ");
					core->cons->line->contents = strdup (cmd);
					buf = r_line_readline ();
					core->cons->line->contents = NULL;
					r_config_set (core->config, "cmd.gprompt", buf);
				}
				break;
			case 'O':
				graph_toggle_simple_mode(g);
				break;
			case 'V':
				graph_toggle_callgraph(g);
				break;
			case 'z':
				g->is_instep = R_TRUE;
				if (r_config_get_i (core->config, "cfg.debug"))
					r_core_cmd0 (core, "ds;.dr*");
				else
					r_core_cmd0 (core, "aes;.dr*");

				ret = graph_reload_nodes(g);
				if (!ret)
					is_error = R_TRUE;
				break;
			case 'Z':
				if (okey == 27) {
					graph_prev_node(g);
				} else {
					// 'Z'
					g->is_instep = R_TRUE;
					if (r_config_get_i (core->config, "cfg.debug"))
						r_core_cmd0 (core, "dso;.dr*");
					else
						r_core_cmd0 (core, "aeso;.dr*");

					ret = graph_reload_nodes(g);
					if (!ret)
						is_error = R_TRUE;
				}
				break;
			case 'x':
				if (r_core_visual_xrefs_x (core))
					exit_graph = R_TRUE;
				break;
			case 'X':
				if (r_core_visual_xrefs_X (core))
					exit_graph = R_TRUE;
				break;
			case 9: // tab
				graph_next_node(g);
				break;
			case '?':
				r_cons_clear00 ();
				r_cons_printf ("Visual Ascii Art graph keybindings:\n"
						" .    - center graph to the current node\n"
						" C    - toggle scr.color\n"
						" hjkl - move node\n"
						" asdw - scroll canvas\n"
						" tab  - select next node\n"
						" TAB  - select previous node\n"
						" t/f  - follow true/false edges\n"
						" e    - toggle edge-lines style (diagonal/square)\n"
						" n    - toggle mini-graph\n"
						" O    - toggle disasm mode\n"
						" u    - select previous node\n"
						" V    - toggle basicblock / call graphs\n"
						" x/X  - jump to xref/ref\n"
						" z/Z  - step / step over\n"
						" R    - relayout\n");
				r_cons_flush ();
				r_cons_any_key (NULL);
				break;
			case 'R':
			case 'r':
				graph_set_layout (g);
				break;
			case 'j':
				if (r_cons_singleton()->mouse_event) {
					switch (mousemode) {
						case 0: // canvas-y
							can->sy += wheelspeed;
							break;
						case 1: // canvas-x
							can->sx += wheelspeed;
							break;
						case 2: // node-y
							get_current_node(g)->y += wheelspeed;
							break;
						case 3: // node-x
							get_current_node(g)->x += wheelspeed;
							break;
					}
				} else {
					get_current_node(g)->y++;
				}
				break;
			case 'k':
				if (r_cons_singleton()->mouse_event) {
					switch (mousemode) {
						case 0: // canvas-y
							can->sy -= wheelspeed;
							break;
						case 1: // canvas-x
							can->sx -= wheelspeed;
							break;
						case 2: // node-y
							get_current_node(g)->y -= wheelspeed;
							break;
						case 3: // node-x
							get_current_node(g)->x -= wheelspeed;
							break;
					}
				} else {
					get_current_node(g)->y--;
				}
				break;
			case 'm':
				mousemode++;
				if (!mousemodes[mousemode])
					mousemode = 0;
				break;
			case 'M':
				mousemode--;
				if (mousemode<0)
					mousemode = 3;
				break;
			case 'h': get_current_node(g)->x--; break;
			case 'l': get_current_node(g)->x++; break;
			case 'J': get_current_node(g)->y += 5; break;
			case 'K': get_current_node(g)->y -= 5; break;
			case 'H': get_current_node(g)->x -= 5; break;
			case 'L': get_current_node(g)->x += 5; break;
					  // scroll
			case '0': can->sx = can->sy = 0; break;
			case 'w': can->sy -= 1; break;
			case 's': can->sy += 1; break;
			case 'a': can->sx -= 1; break;
			case 'd': can->sx += 1; break;
			case 'W': can->sy -= 5; break;
			case 'S': can->sy += 5; break;
			case 'A': can->sx -= 5; break;
			case 'D': can->sx += 5; break;
			case 'e':
				  can->linemode = !!!can->linemode;
				  break;
			case 'n':
				  graph_toggle_small_nodes(g);
				  break;
			case 'u':
				  graph_undo_node(g);
				  break;
			case '.':
				  graph_update_seek (g, g->curnode, R_TRUE);
				  g->is_instep = R_TRUE;
				  break;
			case 't':
				  graph_follow_true(g);
				  break;
			case 'f':
				  graph_follow_false(g);
				  break;
			case '/':
				  r_core_cmd0 (core, "?i highlight;e scr.highlight=`?y`");
				  break;
			case ':':
				  core->vmode = R_FALSE;
				  r_core_visual_prompt_input (core);
				  core->vmode = R_TRUE;
				  break;
			case 'C':
				  can->color = !!!can->color;
				  //r_config_swap (core->config, "scr.color");
				  // refresh graph
				  break;
			case -1: // EOF
			case 'q':
				  exit_graph = R_TRUE;
				  break;
			case 27: // ESC
				  if (r_cons_readchar () == 91) {
					  if (r_cons_readchar () == 90) {
						  if (g->curnode < 1) {
							  int i;
							  for (i = 0; i < g->n_nodes; i++) ;
							  g->curnode = i - 1;
						  } else {
							  g->curnode--;
						  }
					  }
				  }
				  break;
			default:
				  eprintf ("Key %d\n", key);
				  //sleep (1);
				  break;
		}
	}

	graph_free(g);
err_graph_new:
	free (can);
	return !is_error;
}
