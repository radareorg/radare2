/* Copyright radare2 - 2014-2024 - pancake, ret2libc */

#include <r_core.h>
#include <r_vec.h>

R_IPI void visual_refresh(RCore *core);

static RCoreHelpMessage help_msg_visual_graph = {
	":e cmd.gprompt=agft", "show tinygraph in one side",
	"@",            "toggle graph.layout between 0 and 1",
	"[]",           "adjust graph.bb.maxwidth",
	"+/-/0",        "zoom in/out/default",
	";",            "add comment in current basic block",
	". (dot)",      "center graph to the current node",
	", (comma)",    "toggle graph.few",
	"^",            "seek to the first bb of the function",
	"=",            "toggle graph.layout",
	":cmd",         "run radare command",
	"\"",           "toggle graph.refs",
	"#",            "toggle graph.hints",
	"/",            "highlight text",
	"\\",           "scroll the graph canvas to the next highlight location",
	"|",            "set cmd.gprompt",
	"_",            "enter hud selector",
	">",            "show function callgraph (see graph.refs)",
	"<",            "show program callgraph (see graph.refs)",
	"(",            "reverse conditional branch of last instruction in bb",
	")",            "rotate asm.emu and emu.str",
	"%",            "find in disassembly (pdr~sentence) and navigate to it in graph",
	"Home/End",     "go to the top/bottom of the canvas",
	"Page-UP/DOWN", "scroll canvas up/down",
	"b",            "visual browse things",
	"c",            "toggle graph cursor mode",
	"C",            "toggle scr.colors",
	"d",            "rename function",
	"D",            "toggle the mixed graph+disasm mode",
	"e",            "rotate graph.edges (show/hide edges)",
	"E",            "rotate graph.linemode (square/diagonal lines)",
	"F",            "enter flag selector",
	"g",            "go/seek to given offset",
	"G",            "debug trace callgraph (generated with dtc)",
	"hjkl/HJKL",    "scroll canvas or node depending on graph cursor (uppercase for faster)",
	"i/I",          "select input / output nodes by index",
	"mK/'K",        "mark/go to given key (same as in vim or r2 visual)",
	"M",            "change mouse mode (scroll vertical/horizontal)",
	"n/N",          "next/previous scr.nkey (function/flag..)",
	"o([A-Za-z]*)", "follow jmp/call identified by shortcut (like ;[oa])",
	"O",            "toggle asm.pseudo and asm.esil",
	"p/P",          "rotate graph modes (normal, display offsets, minigraph, summary)",
	"q",            "back to Visual mode",
	"r",            "toggle jmphints/leahints",
	"R",            "randomize colors",
	"s/S",          "step / step over",
	"tab",          "select next node",
	"TAB",          "select previous node",
	"t/f",          "follow true/false edges",
	"u/U",          "undo/redo seek",
	"V",            "toggle basicblock / call graphs",
	"w",            "toggle between movements speed 1 and graph.scroll",
	// W            AVAILABLE
	"x/X",          "jump to xref/ref",
	"y",            "toggle graph.comments",
	"Y",            "toggle tiny graph",
	"z",            "toggle node folding",
	"Z",            "toggle basic block folding",
	NULL
};

#if 0
static const char * const mousemodes[] = {
	"canvas-y",
	"canvas-x",
	"node-y",
	"node-x",
	NULL
};
#endif

#define BORDER 3
#define BORDER_WIDTH 4
#define BORDER_HEIGHT 3
#define MARGIN_TEXT_X 2
#define MARGIN_TEXT_Y 2
#define HORIZONTAL_NODE_SPACING 4
#define VERTICAL_NODE_SPACING 2
#define MIN_NODE_WIDTH 22
#define MIN_NODE_HEIGHT BORDER_HEIGHT
#define TITLE_LEN 128
#define DEFAULT_SPEED 1
#define PAGEKEY_SPEED (h / 2)
/* 15 */
#define MINIGRAPH_NODE_TEXT_CUR "<@@@@@@>"
#define MINIGRAPH_NODE_MIN_WIDTH 12
#define MINIGRAPH_NODE_TITLE_LEN 4
#define MINIGRAPH_NODE_CENTER_X 3
#define MININODE_MIN_WIDTH 16

#define ZOOM_STEP 10
#define ZOOM_DEFAULT 100

#define BODY_OFFSETS    0x1
#define BODY_SUMMARY    0x2
#define BODY_COMMENTS   0x4

#define NORMALIZE_MOV(x) ((x) < 0 ? -1 : ((x) > 0 ? 1 : 0))

R_VEC_TYPE (RVecAnalRef, RAnalRef);

static void hash_set(Sdb *db, const void *k, ut64 v) {
	r_strf_var (ks, 32, "%"PFMT64u, (ut64) (size_t) (k));
	sdb_num_set (db, ks, (ut64) (size_t) (v), 0);
}

static ut64 hash_get(Sdb *db, const void *k) {
	r_strf_var (ks, 32, "%"PFMT64u, (ut64) (size_t) (k));
	return sdb_num_get (db, ks, NULL);
}

#define hash_get_rnode(sdb, k) ((RGraphNode *) (size_t) hash_get (sdb, k))
#define hash_get_rlist(sdb, k) ((RList *) (size_t) hash_get (sdb, k))
#define hash_get_int(sdb, k) ((int) (size_t)hash_get (sdb, k))
/* don't use macros for this */
#define get_anode(gn) ((gn)? (RANode *) (gn)->data: NULL)

#define graph_foreach_anode(list, it, pos, anode)\
	if (list) for ((it) = (list)->head; (it) && ((pos) = (it)->data) && (pos) && ((anode) = (RANode *) (pos)->data); (it) = (it)->n)

struct len_pos_t {
	int len;
	int pos;
};

struct dist_t {
	const RGraphNode *from;
	const RGraphNode *to;
	int dist;
};

struct g_cb {
	RAGraph *graph;
	RANodeCallback node_cb;
	RAEdgeCallback edge_cb;
	void *data;
};

typedef struct ascii_edge_t {
	RANode *from;
	RANode *to;
	RList *x, *y;
	bool is_reversed;
	bool is_highlight;
} AEdge;

struct layer_t {
	int n_nodes;
	RGraphNode **nodes;
	int position;
	int height;
	int width;
	int gap;
};

struct agraph_refresh_data {
	RCore *core;
	RAGraph *g;
	RAnalFunction **fcn;
	bool follow_offset;
	int fs;
};

struct r_agraph_location {
	int x;
	int y;
};

#define G(x, y) r_cons_canvas_gotoxy (g->can, x, y)
#define W(x) r_cons_canvas_write (g->can, x)
#define F(x, y, x2, y2, c) r_cons_canvas_fill (g->can, x, y, x2, y2, c)

static bool is_offset(const RAGraph *g) {
	return g->mode == R_AGRAPH_MODE_OFFSET;
}

static bool is_mini(const RAGraph *g) {
	return g->mode == R_AGRAPH_MODE_MINI;
}

static bool is_tiny(const RAGraph *g) {
	return g->is_tiny || g->mode == R_AGRAPH_MODE_TINY;
}

static bool is_summary(const RAGraph *g) {
	return g->mode == R_AGRAPH_MODE_SUMMARY;
}

static bool is_comments(const RAGraph *g) {
	return g->mode == R_AGRAPH_MODE_COMMENTS;
}

static int next_mode(int mode) {
	return (mode + 1) % R_AGRAPH_MODE_MAX;
}

static int prev_mode(int mode) {
	return (mode + R_AGRAPH_MODE_MAX - 1) % R_AGRAPH_MODE_MAX;
}

static RGraphNode *agraph_get_title(const RAGraph *g, RANode *n, bool in) {
	if (!n) {
		return NULL;
	}
	if (!R_STR_ISEMPTY (n->title)) {
		return n->gnode;
	}
	const RList *outnodes = in? n->gnode->in_nodes : n->gnode->out_nodes;
	RGraphNode *gn;
	RListIter *iter;
	r_list_foreach (outnodes, iter, gn) {
		RANode *an = gn->data;
		return agraph_get_title (g, an, in);
	}
	return NULL;
}

static int mode2opts(const RAGraph *g) {
	int opts = 0;
	if (is_offset (g)) {
		opts |= BODY_OFFSETS;
	}
	if (is_comments (g)) {
		opts |= BODY_COMMENTS;
	}
	if (is_summary (g)) {
		opts |= BODY_SUMMARY;
	}
	return opts;
}

// duplicated from visual.c
static void rotateAsmemu(RCore *core) {
	const bool isEmuStr = r_config_get_b (core->config, "emu.str");
	const bool isEmu = r_config_get_b (core->config, "asm.emu");
	if (isEmu) {
		if (isEmuStr) {
			r_config_set_b (core->config, "emu.str", false);
		} else {
			r_config_set_b (core->config, "asm.emu", false);
		}
	} else {
		r_config_set_b (core->config, "emu.str", true);
	}
}

static void showcursor(RCore *core, int x) {
	if (!x) {
		bool wheel = r_config_get_b (core->config, "scr.wheel");
		if (wheel) {
			r_cons_enable_mouse (true);
		}
	} else {
		r_cons_enable_mouse (false);
	}
	r_cons_show_cursor (x);
}

static char *get_title(ut64 addr) {
	return r_str_newf ("0x%"PFMT64x, addr);
}

static int agraph_refresh(struct agraph_refresh_data *grd);

static void update_node_dimension(const RGraph *g, int is_mini, int zoom, int edgemode, bool callgraph, int layout) {
	const RList *nodes = r_graph_get_nodes (g);
	RGraphNode *gn;
	RListIter *it;
	RANode *n;
	graph_foreach_anode (nodes, it, gn, n) {
		if (is_mini) {
			n->h = 1;
			n->w = MINIGRAPH_NODE_MIN_WIDTH;
		} else if (n->is_mini) {
			n->h = 1;
			n->w = MININODE_MIN_WIDTH;
		} else {
			n->w = r_str_bounds (n->body, (int *) &n->h);
			ut32 len = strlen (n->title) + MARGIN_TEXT_X;
			if (len > INT_MAX) {
				len = INT_MAX;
			}
			if (len > n->w) {
				n->w = len;
			}
			// n->w = n->w; //R_MIN (n->w, (int)len);
			n->w += BORDER_WIDTH;
			n->h += BORDER_HEIGHT;
			/* scale node by zoom */
			n->w = R_MAX (MIN_NODE_WIDTH, (n->w * zoom) / 100);
			n->h = R_MAX (MIN_NODE_HEIGHT, (n->h * zoom) / 100);

			if (edgemode == 2 && !callgraph) {
				if (!layout) {
					n->w = R_MAX (n->w, (r_list_length (n->gnode->out_nodes) * 2 + 1) + R_EDGES_X_INC * 2);
					n->w = R_MAX (n->w, (r_list_length (n->gnode->in_nodes) * 2 + 1) + R_EDGES_X_INC * 2);
				} else {
					n->h = R_MAX (n->h, (r_list_length (n->gnode->out_nodes) + 1) + R_EDGES_X_INC);
					n->h = R_MAX (n->h, (r_list_length (n->gnode->in_nodes) + 1) + R_EDGES_X_INC);
				}
			}
		}
	}
}

static void append_shortcut(const RAGraph *g, char *title, char *nodetitle, int left) {
	char *k = r_str_newf ("agraph.nodes.%s.shortcut", nodetitle);
	const char *shortcut = sdb_const_get (g->db, k, 0);
	if (shortcut) {
		size_t n = strlen (title);
		if (g->can->color) {
			// XXX: do not hardcode color here
			free (k);
			k = r_str_newf (Color_YELLOW"[o%s]"Color_RESET, shortcut);
			snprintf (title + n, left, "%s", k);
		} else {
			free (k);
			k = r_str_newf ("[o%s]", shortcut);
			snprintf (title + n, left, "%s", k);
		}
	}
	free (k);
}

static void mini_RANode_print(const RAGraph *g, const RANode *n, int cur, bool details) {
	char title[TITLE_LEN];
	int x, delta_x = 0;

	if (!G (n->x + MINIGRAPH_NODE_CENTER_X, n->y) &&
	    !G (n->x + MINIGRAPH_NODE_CENTER_X + n->w, n->y)) {
		return;
	}

	x = n->x + MINIGRAPH_NODE_CENTER_X + g->can->sx;
	if (x < 0) {
		delta_x = -x;
	}
	if (!G (n->x + MINIGRAPH_NODE_CENTER_X + delta_x, n->y)) {
		return;
	}

	if (details) {
		if (cur) {
			W (&MINIGRAPH_NODE_TEXT_CUR[delta_x]);
			(void) G (-g->can->sx, -g->can->sy + 2);
			snprintf (title, sizeof (title) - 1, "[ %s ]", n->title);
			W (title);
			if (g->discroll > 0) {
				char *body = r_str_ansi_crop (n->body, 0, g->discroll, -1, -1);
				(void) G (-g->can->sx, -g->can->sy + 3);
				W (body);
				free (body);
			} else {
				(void) G (-g->can->sx, -g->can->sy + 3);
				W (n->body);
			}
		} else {
			char *str = "____";
			if (n->title) {
				int l = strlen (n->title);
				str = n->title;
				if (l > MINIGRAPH_NODE_TITLE_LEN) {
					str += l - MINIGRAPH_NODE_TITLE_LEN;
				}
			}
			if (g->can->color) {
				snprintf (title, sizeof (title) - 1, "%s__%s__", Color_RESET, str);
			} else {
				snprintf (title, sizeof (title) - 1, "__%s__", str);
			}
			append_shortcut (g, title, n->title, sizeof (title) - strlen (title));
			char *res = r_str_ansi_crop (title, delta_x, 0, 20, 1);
			W (res);
			free (res);
		}
	} else {
		snprintf (title, sizeof (title) - 1,
			cur? "[ %s ]": "  %s  ", n->title);
		W (title);
	}
	return;
}

static void tiny_RANode_print(const RAGraph *g, const RANode *n, int cur) {
	G (n->x, n->y);
	if (cur) {
		W ("##");
	} else {
		W ("*");
	}
}

static char *get_node_bgcolor(int color, int cur) {
//	return r_str_newf ("%s", Color_BGRED);
#if 1
	RCons *cons = r_cons_singleton ();
	if (color == -1) {
		return cur ? cons->context->pal.graph_box2 : cons->context->pal.graph_box;
	}
	return color
		? (color == R_ANAL_DIFF_TYPE_MATCH
			? cons->context->pal.diff_match
			: color == R_ANAL_DIFF_TYPE_UNMATCH
				? cons->context->pal.diff_unmatch
				: cons->context->pal.diff_new)
		: cons->context->pal.diff_unknown;
#endif
}

static char *get_node_color(int color, int cur) {
	RCons *cons = r_cons_singleton ();
	if (color == -1) {
		return cur ? cons->context->pal.graph_box2 : cons->context->pal.graph_box;
	}
	return color
		? (color == R_ANAL_DIFF_TYPE_MATCH
			? cons->context->pal.diff_match
			: color == R_ANAL_DIFF_TYPE_UNMATCH
				? cons->context->pal.diff_unmatch
				: cons->context->pal.diff_new)
		: cons->context->pal.diff_unknown;
}

static void normal_RANode_print(const RAGraph *g, const RANode *n, int cur) {
	ut32 center_x = 0, center_y = 0;
	ut32 delta_x = 0, delta_txt_x = 0;
	ut32 delta_y = 0, delta_txt_y = 0;
	char title[TITLE_LEN];
	char *body;
	int x, y;
	int color = n->difftype;
	const bool showTitle = g->show_node_titles;
	const bool showBody = g->show_node_body;
	if (n->color) {
#if 0
		const char *pad = r_str_pad ('#', n->w);
		char *f = r_str_newf ("%s%s%s%s", n->color, pad, Color_RESET, nc);
		G (n->x, n->y);
		W (f);
		free (f);
#endif
		// r_cons_canvas_bgfill (g->can, n->x-1, n->y-1, n->w+2, n->h+2, n->color);
		r_cons_canvas_box (g->can, n->x-1, n->y, n->w+2, n->h, n->color);
	}

	x = n->x + g->can->sx;
	y = n->y + g->can->sy;
	if (x + MARGIN_TEXT_X < 0) {
		delta_x = -(x + MARGIN_TEXT_X);
	}
	if (x + n->w < -MARGIN_TEXT_X) {
		return;
	}
	if (y < -1) {
		delta_y = R_MIN (n->h - BORDER_HEIGHT - 1, -y - MARGIN_TEXT_Y);
	}
	if (g->show_node_bubble) {
		r_cons_canvas_bgfill (g->can, n->x, n->y, n->w, n->h, get_node_bgcolor (color, cur));
	}
	/* print the title */
	if (showTitle) {
		if (cur) {
			snprintf (title, sizeof (title) - 1, "[%s]", n->title);
		} else {
			char *color = g->can->color ? Color_RESET : "";
			snprintf (title, sizeof (title) - 1, " %s%s ", color, n->title);
			append_shortcut (g, title, n->title, sizeof (title) - strlen (title));
		}
		if (g->bb_maxwidth > 0 && r_str_len_utf8_ansi (title) > g->bb_maxwidth) {
			char *pos = (char *)r_str_ansi_chrn (title, g->bb_maxwidth);
			if (pos) {
				*pos = 0;
			}
		}
		if ((delta_x < strlen (title)) && G (n->x + MARGIN_TEXT_X + delta_x, n->y + 1)) {
			char *res = r_str_ansi_crop (title, delta_x, 0, n->w - BORDER_WIDTH, 1);
			W (res);
			W (Color_RESET);
			free (res);
		}
	}

	/* print the body */
	if (g->zoom > ZOOM_DEFAULT) {
		center_x = (g->zoom - ZOOM_DEFAULT) / 10;
		center_y = (g->zoom - ZOOM_DEFAULT) / 30;
		delta_txt_x = R_MIN (delta_x, center_x);
		delta_txt_y = R_MIN (delta_y, center_y);
	}
	if (showBody) {
		if (G (n->x + MARGIN_TEXT_X + delta_x + center_x - delta_txt_x,
					n->y + MARGIN_TEXT_Y + delta_y + center_y - delta_txt_y)) {
			ut32 body_x = center_x >= delta_x? 0: delta_x - center_x;
			ut32 body_y = center_y >= delta_y? 0: delta_y - center_y;
			ut32 body_h = BORDER_HEIGHT >= n->h? 1: n->h - BORDER_HEIGHT;

			if (g->zoom < ZOOM_DEFAULT) {
				body_h--;
			}
			if (body_y + 1 <= body_h) {
				body = r_str_ansi_crop (n->body,
						body_x, body_y,
						n->w - BORDER_WIDTH,
						body_h);
				if (body) {
					W (body);
					if (g->zoom < ZOOM_DEFAULT) {
						W ("\n");
					}
					free (body);
				} else {
					W (n->body);
				}
			}
			/* print some dots when the body is cropped because of zoom */
			if (n->body && *n->body) {
				if (body_y <= body_h && g->zoom < ZOOM_DEFAULT) {
					char *dots = "...";
					if (delta_x < strlen (dots)) {
						dots += delta_x;
						W (dots);
					}
				}
			}
		}
	}

#if 1
	// TODO: check if node is traced or not and show proper color
	// This info must be stored inside RANode* from RCore*
	const char *nc = get_node_color (color, cur);
	if (g->show_node_bubble) {
		r_cons_canvas_bgfill (g->can, n->x, n->y, n->w, n->h, get_node_bgcolor (color, cur));
	// r_cons_canvas_circle (g->can, n->x, n->y, n->w, n->h, get_node_color (color, cur));
	} else {
		r_cons_canvas_box (g->can, n->x, n->y, n->w, n->h, nc);
	}
	if (n->color) {
#if 0
		const char *pad = r_str_pad ('#', n->w);
		char *f = r_str_newf ("%s%s%s%s", n->color, pad, Color_RESET, nc);
		G (n->x, n->y);
		W (f);
		free (f);
#endif
		r_cons_canvas_box (g->can, n->x - 1, n->y, n->w + 2, n->h, n->color);
	}
#endif
}

static int **get_crossing_matrix(const RGraph *g, const struct layer_t layers[], int maxlayer, int i, int from_up, int *n_rows) {
	int j, len = layers[i].n_nodes;

	int **m = R_NEWS0 (int *, len);
	if (!m) {
		return NULL;
	}
	for (j = 0; j < len; j++) {
		m[j] = R_NEWS0 (int, len);
		if (!m[j]) {
			goto err_row;
		}
	}
	/* calculate crossings between layer i and layer i-1 */
	/* consider the crossings generated by each pair of edges */
	if (i > 0 && from_up) {
		if (r_cons_is_breaked ()) {
			goto err_row;
		}
		for (j = 0; j < layers[i - 1].n_nodes; j++) {
			const RGraphNode *gj = layers[i - 1].nodes[j];
			const RList *neigh = r_graph_get_neighbours (g, gj);
			RGraphNode *gk;
			RListIter *itk;

			r_list_foreach (neigh, itk, gk) {
				int s;
				// skip self-loop
				if (gj == gk) {
					continue;
				}
				for (s = 0; s < j; s++) {
					const RGraphNode *gs = layers[i - 1].nodes[s];
					const RList *neigh_s = r_graph_get_neighbours (g, gs);
					RGraphNode *gt;
					RListIter *itt;

					r_list_foreach (neigh_s, itt, gt) {
						const RANode *ak, *at; /* k and t should be "indexes" on layer i */
						if (gt == gk || gt == gs) {
							continue;
						}
						ak = get_anode (gk);
						at = get_anode (gt);
						if (ak->layer != i || at->layer != i) {
							// this should never happen
							// but it happens if we do graph.dummy = false, so better hide it for now
#if 0
							R_LOG_WARN ("%s (%d) or \"%s\" (%d) are not on the right layer (%d)",
								ak->title, ak->layer,
								at->title, at->layer,
								i);
#endif
							continue;
						}
						m[ak->pos_in_layer][at->pos_in_layer]++;
					}
				}
			}
		}
	}

	/* calculate crossings between layer i and layer i+1 */
	if (i < maxlayer - 1 && !from_up) {
		if (r_cons_is_breaked ()) {
			goto err_row;
		}
		for (j = 0; j < layers[i].n_nodes; j++) {
			const RGraphNode *gj = layers[i].nodes[j];
			const RList *neigh = r_graph_get_neighbours (g, gj);
			const RANode *ak, *aj = get_anode (gj);
			RGraphNode *gk;
			RListIter *itk;

			if (r_cons_is_breaked ()) {
				goto err_row;
			}
			graph_foreach_anode (neigh, itk, gk, ak) {
				int s;
				for (s = 0; s < layers[i].n_nodes; s++) {
					const RGraphNode *gs = layers[i].nodes[s];
					const RList *neigh_s;
					RGraphNode *gt;
					RListIter *itt;
					const RANode *at, *as = get_anode (gs);

					if (gs == gj) {
						continue;
					}
					neigh_s = r_graph_get_neighbours (g, gs);
					graph_foreach_anode (neigh_s, itt, gt, at) {
						if (at->pos_in_layer < ak->pos_in_layer) {
							m[aj->pos_in_layer][as->pos_in_layer]++;
						}
					}
				}
			}
		}
	}

	if (n_rows) {
		*n_rows = len;
	}
	return m;

err_row:
	for (i = 0; i < len; i++) {
		free (m[i]);
	}
	free (m);
	return NULL;
}

static int layer_sweep(const RGraph *g, const struct layer_t layers[], int maxlayer, int i, int from_up) {
	RGraphNode *u, *v;
	const RANode *au, *av;
	int n_rows, j, changed = false;
	int len = layers[i].n_nodes;

	int **cross_matrix = get_crossing_matrix (g, layers, maxlayer, i, from_up, &n_rows);
	if (!cross_matrix) {
		return -1; // ERROR HAPPENS
	}

	for (j = 0; j < len - 1; j++) {
		int auidx, avidx;

		u = layers[i].nodes[j];
		v = layers[i].nodes[j + 1];
		au = get_anode (u);
		av = get_anode (v);
		auidx = au->pos_in_layer;
		avidx = av->pos_in_layer;

		if (cross_matrix[auidx][avidx] > cross_matrix[avidx][auidx]) {
			/* swap elements */
			layers[i].nodes[j] = v;
			layers[i].nodes[j + 1] = u;
			changed = true;
		}
	}

	/* update position in the layer of each node. During the swap of some
	 * elements we didn't swap also the pos_in_layer because the cross_matrix
	 * is indexed by it, so do it now! */
	for (j = 0; j < layers[i].n_nodes; j++) {
		RANode *n = get_anode (layers[i].nodes[j]);
		n->pos_in_layer = j;
	}

	for (j = 0; j < n_rows; j++) {
		free (cross_matrix[j]);
	}
	free (cross_matrix);
	return changed;
}

static void view_cyclic_edge(const RGraphEdge *e, const RGraphVisitor *vis) {
	const RAGraph *g = (RAGraph *) vis->data;
	RGraphEdge *new_e = R_NEW0 (RGraphEdge);
	if (!new_e) {
		return;
	}
	new_e->from = e->from;
	new_e->to = e->to;
	new_e->nth = e->nth;
	r_list_append (g->back_edges, new_e);
}

// wtf?long_edges leaks?
static void view_dummy(const RGraphEdge *e, const RGraphVisitor *vis) {
	const RANode *a = get_anode (e->from);
	const RANode *b = get_anode (e->to);
	RList *long_edges = (RList *) vis->data;
	if (!a || !b) {
		return;
	}
	if (R_ABS (a->layer - b->layer) > 1) {
		RGraphEdge *new_e = R_NEW0 (RGraphEdge);
		if (!new_e) {
			return;
		}
		new_e->from = e->from;
		new_e->to = e->to;
		new_e->nth = e->nth;
		r_list_append (long_edges, new_e);
	}
}

/* find a set of edges that, removed, makes the graph acyclic */
/* invert the edges identified in the previous step */
static void remove_cycles(RAGraph *g) {
	RGraphVisitor cyclic_vis = {
		NULL, NULL, NULL, NULL, NULL, NULL
	};
	const RGraphEdge *e;
	const RListIter *it;

	g->back_edges = r_list_newf (free);
	cyclic_vis.back_edge = (RGraphEdgeCallback) view_cyclic_edge;
	cyclic_vis.data = g;
	r_graph_dfs (g->graph, &cyclic_vis);

	r_list_foreach (g->back_edges, it, e) {
		RANode *from = e->from? get_anode (e->from): NULL;
		RANode *to = e->to? get_anode (e->to): NULL;
		if (from && to) {
			r_agraph_del_edge (g, from, to);
			r_agraph_add_edge_at (g, to, from, e->nth);
		}
	}
}

static void add_sorted(RGraphNode *n, RGraphVisitor *vis) {
	RList *l = (RList *) vis->data;
	r_list_prepend (l, n);
}

/* assign a layer to each node of the graph.
 *
 * It visits the nodes of the graph in the topological sort, so that every time
 * you visit a node, you can be sure that you have already visited all nodes
 * that can lead to that node and thus you can easily compute the layer based
 * on the layer of these "parent" nodes. */
static void assign_layers(const RAGraph *g) {
	RGraphVisitor layer_vis = {
		NULL, NULL, NULL, NULL, NULL, NULL
	};
	const RGraphNode *gn;
	const RListIter *it;
	RANode *n;
	RList *topological_sort = r_list_new ();

	layer_vis.data = topological_sort;
	layer_vis.finish_node = (RGraphNodeCallback) add_sorted;
	r_graph_dfs (g->graph, &layer_vis);

	graph_foreach_anode (topological_sort, it, gn, n) {
		const RList *innodes = r_graph_innodes (g->graph, gn);
		RListIter *it;
		RGraphNode *prev;
		RANode *preva;

		n->layer = 0;
		graph_foreach_anode (innodes, it, prev, preva) {
			if (preva->layer + 1 > n->layer) {
				n->layer = preva->layer + 1;
			}
		}
	}

	r_list_free (topological_sort);
}

static int find_edge(const RGraphEdge *a, const RGraphEdge *b) {
	return a->from == b->to && a->to == b->from? 0: 1;
}

static bool is_reversed(const RAGraph *g, const RGraphEdge *e) {
	return (bool)r_list_find (g->back_edges, e, (RListComparator) find_edge);
}

/* add dummy nodes when there are edges that span multiple layers */
static void create_dummy_nodes(RAGraph *g) {
	if (!g->dummy) {
		return;
	}
	RGraphVisitor dummy_vis = {
		NULL, NULL, NULL, NULL, NULL, NULL
	};
	const RListIter *it;
	const RGraphEdge *e;

	g->long_edges = r_list_newf ((RListFree)free);
	dummy_vis.data = g->long_edges;
	dummy_vis.tree_edge = (RGraphEdgeCallback) view_dummy;
	dummy_vis.fcross_edge = (RGraphEdgeCallback) view_dummy;
	r_graph_dfs (g->graph, &dummy_vis);

	r_list_foreach (g->long_edges, it, e) {
		RANode *from = get_anode (e->from);
		RANode *to = get_anode (e->to);
		int diff_layer = R_ABS (from->layer - to->layer);
		RANode *prev = get_anode (e->from);
		int i, nth = e->nth;

		r_agraph_del_edge (g, from, to);
		for (i = 1; i < diff_layer; i++) {
			RANode *dummy = r_agraph_add_node (g, NULL, NULL, NULL);
			if (!dummy) {
				return;
			}
			dummy->is_dummy = true;
			dummy->layer = from->layer + i;
			dummy->is_reversed = is_reversed (g, e);
			dummy->w = 1;
			r_agraph_add_edge_at (g, prev, dummy, nth);

			prev = dummy;
			nth = -1;
		}
		r_graph_add_edge (g->graph, prev->gnode, e->to);
	}
}

/* create layers and assign an initial ordering of the nodes into them */
static void create_layers(RAGraph *g) {
	const RList *nodes = r_graph_get_nodes (g->graph);
	RGraphNode *gn;
	const RListIter *it;
	RANode *n;
	int i;

	/* identify max layer */
	g->n_layers = 0;
	graph_foreach_anode (nodes, it, gn, n) {
		if (n->layer > g->n_layers) {
			g->n_layers = n->layer;
		}
	}

	/* create a starting ordering of nodes for each layer */
	g->n_layers++;
	if (sizeof (struct layer_t) * g->n_layers < g->n_layers) {
		return;
	}
	g->layers = R_NEWS0 (struct layer_t, g->n_layers);

	graph_foreach_anode (nodes, it, gn, n) {
		g->layers[n->layer].n_nodes++;
	}

	for (i = 0; i < g->n_layers; i++) {
		if (sizeof (RGraphNode *) * g->layers[i].n_nodes < g->layers[i].n_nodes) {
			continue;
		}
		g->layers[i].nodes = R_NEWS0 (RGraphNode *,
			1 + g->layers[i].n_nodes);
		g->layers[i].position = 0;
	}
	graph_foreach_anode (nodes, it, gn, n) {
		n->pos_in_layer = g->layers[n->layer].position;
		g->layers[n->layer].nodes[g->layers[n->layer].position++] = gn;
	}
}

/* layer-by-layer sweep */
/* it permutes each layer, trying to find the best ordering for each layer
 * to minimize the number of crossing edges */
static void minimize_crossings(const RAGraph *g) {
	int i, cross_changed, max_changes = 4096;

	do {
		cross_changed = false;
		max_changes--;

		for (i = 0; i < g->n_layers; i++) {
			int rc = layer_sweep (g->graph, g->layers, g->n_layers, i, true);
			if (rc == -1) {
				return;
			}
			cross_changed |= !!rc;
		}
	} while (cross_changed && max_changes);

	max_changes = 4096;

	do {
		cross_changed = false;
		max_changes--;

		for (i = g->n_layers - 1; i >= 0; i--) {
			int rc = layer_sweep (g->graph, g->layers, g->n_layers, i, false);
			if (rc == -1) {
				return;
			}
			cross_changed |= !!rc;
		}
	} while (cross_changed && max_changes);
}

static int find_dist(const struct dist_t *a, const struct dist_t *b) {
	return a->from == b->from && a->to == b->to? 0: 1;
}

/* returns the distance between two nodes */
/* if the distance between two nodes were explicitly set, returns that;
 * otherwise calculate the distance of two nodes on the same layer */
static int dist_nodes(const RAGraph *g, const RGraphNode *a, const RGraphNode *b) {
	struct dist_t d;
	const RANode *aa, *ab;
	RListIter *it;
	int res = 0;

	if (g->dists) {
		d.from = a;
		d.to = b;
		it = r_list_find (g->dists, &d, (RListComparator) find_dist);
		if (it) {
			struct dist_t *old = (struct dist_t *) r_list_iter_get_data (it);
			return old->dist;
		}
	}

	aa = get_anode (a);
	ab = get_anode (b);
	if (aa && ab && aa->layer == ab->layer) {
		int i;

		res = aa == ab && !aa->is_reversed? HORIZONTAL_NODE_SPACING: 0;
		for (i = aa->pos_in_layer; i < ab->pos_in_layer; i++) {
			const RGraphNode *cur = g->layers[aa->layer].nodes[i];
			const RGraphNode *next = g->layers[aa->layer].nodes[i + 1];
			const RANode *anext = get_anode (next);
			const RANode *acur = get_anode (cur);
			int found = false;

			if (g->dists) {
				d.from = cur;
				d.to = next;
				it = r_list_find (g->dists, &d, (RListComparator) find_dist);
				if (it) {
					struct dist_t *old = (struct dist_t *) r_list_iter_get_data (it);
					res += old->dist;
					found = true;
				}
			}

			if (acur && anext && !found) {
				int space = HORIZONTAL_NODE_SPACING;
				if (acur->is_reversed && anext->is_reversed) {
					if (!acur->is_reversed) {
						res += acur->w / 2;
					} else if (!anext->is_reversed) {
						res += anext->w / 2;
					}
					res += 1;
				} else {
					res += acur->w / 2 + anext->w / 2 + space;
				}
			}
		}
	}

	return res;
}

/* explicitly set the distance between two nodes on the same layer */
static void set_dist_nodes(const RAGraph *g, int l, int cur, int next) {
	struct dist_t *d, find_el;
	const RGraphNode *vi, *vip;
	const RANode *avi, *avip;
	RListIter *it;

	if (!g->dists) {
		return;
	}
	vi = g->layers[l].nodes[cur];
	vip = g->layers[l].nodes[next];
	avi = get_anode (vi);
	avip = get_anode (vip);

	find_el.from = vi;
	find_el.to = vip;
	it = r_list_find (g->dists, &find_el, (RListComparator) find_dist);
	d = it? (struct dist_t *) r_list_iter_get_data (it): R_NEW0 (struct dist_t);

	d->from = vi;
	d->to = vip;
	d->dist = (avip && avi)? avip->x - avi->x: 0;
	if (!it) {
		r_list_push (g->dists, d);
	}
}

static inline int is_valid_pos(const RAGraph *g, int l, int pos) {
	return pos >= 0 && pos < g->layers[l].n_nodes;
}

/* computes the set of vertical classes in the graph */
/* if v is an original node, L(v) = { v }
 * if v is a dummy node, L(v) is the set of all the dummies node that belongs
 *      to the same long edge */
static Sdb *compute_vertical_nodes(const RAGraph *g) {
	Sdb *res = sdb_new0 ();
	int i, j;

	for (i = 0; i < g->n_layers; i++) {
		for (j = 0; j < g->layers[i].n_nodes; j++) {
			RGraphNode *gn = g->layers[i].nodes[j];
			const RList *Ln = hash_get_rlist (res, gn);
			const RANode *an = get_anode (gn);

			if (!Ln) {
				RList *vert = r_list_new ();
				hash_set (res, gn, (size_t) vert);
				if (an->is_dummy) {
					RGraphNode *next = gn;
					const RANode *anext = get_anode (next);

					while (anext->is_dummy) {
						r_list_append (vert, next);
						next = r_graph_nth_neighbour (g->graph, next, 0);
						if (!next) {
							break;
						}
						anext = get_anode (next);
					}
				} else {
					r_list_append (vert, gn);
				}
			}
		}
	}

	return res;
}

/* computes left or right classes, used to place dummies node */
/* classes respect three properties:
 * - v E C
 * - w E C => L(v) is a subset of C
 * - w E C, the s+(w) exists and is not in any class yet => s+(w) E C */
static RList **compute_classes(const RAGraph *g, Sdb *v_nodes, int is_left, int *n_classes) {
	int i, j, c;
	RList **res = R_NEWS0 (RList *, g->n_layers);
	RGraphNode *gn;
	const RListIter *it;
	RANode *n;

	graph_foreach_anode (r_graph_get_nodes (g->graph), it, gn, n) {
		n->klass = -1;
	}

	for (i = 0; i < g->n_layers; i++) {
		c = i;

		for (j = is_left? 0: g->layers[i].n_nodes - 1;
		     (is_left && j < g->layers[i].n_nodes) || (!is_left && j >= 0);
		     j = is_left? j + 1: j - 1) {
			const RGraphNode *gj = g->layers[i].nodes[j];
			const RANode *aj = get_anode (gj);

			if (aj->klass == -1) {
				const RList *laj = hash_get_rlist (v_nodes, gj);

				if (!res[c]) {
					res[c] = r_list_new ();
				}
				graph_foreach_anode (laj, it, gn, n) {
					r_list_append (res[c], gn);
					n->klass = c;
				}
			} else {
				c = aj->klass;
			}
		}
	}

	if (n_classes) {
		*n_classes = g->n_layers;
	}
	return res;
}

static int cmp_dist(const size_t a, const size_t b) {
	return (a < b) - (a > b);
}

static RGraphNode *get_sibling(const RAGraph *g, const RANode *n, int is_left, int is_adjust_class) {
	RGraphNode *res = NULL;
	int pos = n->pos_in_layer;

	if ((is_left && is_adjust_class) || (!is_left && !is_adjust_class)) {
		pos++;
	} else {
		pos--;
	}

	if (is_valid_pos (g, n->layer, pos)) {
		res = g->layers[n->layer].nodes[pos];
	}
	return res;
}

static int adjust_class_val(const RAGraph *g, const RGraphNode *gn, const RGraphNode *sibl, Sdb *res, int is_left) {
	if (is_left) {
		return hash_get_int (res, sibl) - hash_get_int (res, gn) - dist_nodes (g, gn, sibl);
	}
	return hash_get_int (res, gn) - hash_get_int (res, sibl) - dist_nodes (g, sibl, gn);
}

/* adjusts the position of previously placed left/right classes */
/* tries to place classes as close as possible */
static void adjust_class(const RAGraph *g, int is_left, RList **classes, Sdb *res, int c) {
	const RGraphNode *gn;
	const RListIter *it;
	const RANode *an;
	int dist = 0;
	bool is_first = true;

	graph_foreach_anode (classes[c], it, gn, an) {
		const RGraphNode *sibling = get_sibling (g, an, is_left, true);
		if (!sibling) {
			continue;
		}
		const RANode *sibl_anode = get_anode (sibling);
		if (sibl_anode->klass == c) {
			continue;
		}
		int v = adjust_class_val (g, gn, sibling, res, is_left);
		dist = is_first? v: R_MIN (dist, v);
		is_first = false;
	}

	if (is_first) {
		RList *heap = r_list_new ();

		graph_foreach_anode (classes[c], it, gn, an) {
			const RList *neigh = r_graph_all_neighbours (g->graph, gn);
			const RGraphNode *gk;
			const RListIter *itk;
			const RANode *ak;

			graph_foreach_anode (neigh, itk, gk, ak) {
				if (ak->klass < c) {
					size_t d = (ak->x - an->x);
					if (d > 0) {
						r_list_append (heap, (void *) d);
					}
				}
			}
		}
		int len = r_list_length (heap);
		if (len == 0) {
			dist = 0;
		} else {
			r_list_sort (heap, (RListComparator) cmp_dist);
			dist = (int) (size_t) r_list_get_n (heap, len / 2);
		}
		r_list_free (heap);
	}

	graph_foreach_anode (classes[c], it, gn, an) {
		const int old_val = hash_get_int (res, gn);
		const int new_val = is_left? old_val + dist: old_val - dist;
		hash_set (res, gn, new_val);
	}
}

static int place_nodes_val(const RAGraph *g, const RGraphNode *gn, const RGraphNode *sibl, Sdb *res, int is_left) {
	if (is_left) {
		return hash_get_int (res, sibl) + dist_nodes (g, sibl, gn);
	}
	return hash_get_int (res, sibl) - dist_nodes (g, gn, sibl);
}

static int place_nodes_sel_p(int newval, int oldval, int is_first, int is_left) {
	if (is_first) {
		return newval;
	}
	if (is_left) {
		return R_MAX (oldval, newval);
	}
	return R_MIN (oldval, newval);
}

/* places left/right the nodes of a class */
static void place_nodes(const RAGraph *g, const RGraphNode *gn, int is_left, Sdb *v_nodes, RList **classes, Sdb *res, Sdb *placed) {
	const RList *lv = hash_get_rlist (v_nodes, gn);
	int p = 0, v, is_first = true;
	const RGraphNode *gk;
	const RListIter *itk;
	const RANode *ak;

	graph_foreach_anode (lv, itk, gk, ak) {
		const RGraphNode *sibling;
		const RANode *sibl_anode;

		sibling = get_sibling (g, ak, is_left, false);
		if (!sibling) {
			continue;
		}
		sibl_anode = get_anode (sibling);
		if (ak->klass == sibl_anode->klass) {
			if (!hash_get (placed, sibling)) {
				place_nodes (g, sibling, is_left, v_nodes, classes, res, placed);
			}

			v = place_nodes_val (g, gk, sibling, res, is_left);
			p = place_nodes_sel_p (v, p, is_first, is_left);
			is_first = false;
		}
	}

	if (is_first) {
		p = is_left? 0: 50;
	}

	graph_foreach_anode (lv, itk, gk, ak) {
		hash_set (res, gk, p);
		hash_set (placed, gk, true);
	}
}

/* computes the position to the left/right of all the nodes */
static Sdb *compute_pos(const RAGraph *g, int is_left, Sdb *v_nodes) {
	int n_classes, i;

	RList **classes = compute_classes (g, v_nodes, is_left, &n_classes);
	if (!classes) {
		return NULL;
	}

	Sdb *res = sdb_new0 ();
	Sdb *placed = sdb_new0 ();
	for (i = 0; i < n_classes; i++) {
		const RGraphNode *gn;
		const RListIter *it;

		r_list_foreach (classes[i], it, gn) {
			if (!hash_get_rnode (placed, gn)) {
				place_nodes (g, gn, is_left, v_nodes, classes, res, placed);
			}
		}

		adjust_class (g, is_left, classes, res, i);
	}

	sdb_free (placed);
	for (i = 0; i < n_classes; i++) {
		if (classes[i]) {
			r_list_free (classes[i]);
		}
	}
	free (classes);
	return res;
}

static int free_vertical_nodes_cb(void *user UNUSED, const char *k UNUSED, const char *v) {
	r_list_free ((RList *) (size_t) sdb_atoi (v));
	return 1;
}

/* calculates position of all nodes, but in particular dummies nodes */
/* computes two different placements (called "left"/"right") and set the final
 * position of each node to the average of the values in the two placements */
static void place_dummies(const RAGraph *g) {
	const RGraphNode *gn;
	const RListIter *it;
	RANode *n;

	Sdb *vertical_nodes = compute_vertical_nodes (g);
	if (!vertical_nodes) {
		return;
	}
	Sdb *xminus = compute_pos (g, true, vertical_nodes);
	if (!xminus) {
		goto xminus_err;
	}
	Sdb *xplus = compute_pos (g, false, vertical_nodes);
	if (!xplus) {
		goto xplus_err;
	}

	const RList *nodes = r_graph_get_nodes (g->graph);
	graph_foreach_anode (nodes, it, gn, n) {
		n->x = (hash_get_int (xminus, gn) + hash_get_int (xplus, gn)) / 2;
	}

	sdb_free (xplus);
xplus_err:
	sdb_free (xminus);
xminus_err:
	sdb_foreach (vertical_nodes, (SdbForeachCallback)free_vertical_nodes_cb, NULL);
	sdb_free (vertical_nodes);
}

static RGraphNode *get_right_dummy(const RAGraph *g, const RGraphNode *n) {
	const RANode *an = get_anode (n);
	if (!an) {
		return NULL;
	}
	int k, layer = an->layer;

	for (k = an->pos_in_layer + 1; k < g->layers[layer].n_nodes; k++) {
		RGraphNode *gk = g->layers[layer].nodes[k];
		const RANode *ak = get_anode (gk);
		if (!ak) {
			break;
		}

		if (ak->is_dummy) {
			return gk;
		}
	}
	return NULL;
}

static void adjust_directions(const RAGraph *g, int i, int from_up, Sdb *D, Sdb *P) {
	const RGraphNode *vm = NULL, *wm = NULL;
	const RANode *vma = NULL, *wma = NULL;
	int j, d = from_up? 1: -1;

	if (i + d < 0 || i + d >= g->n_layers) {
		return;
	}
	for (j = 0; j < g->layers[i + d].n_nodes; j++) {
		const RGraphNode *wp, *vp = g->layers[i + d].nodes[j];
		const RANode *wpa, *vpa = get_anode (vp);

		if (!vpa || !vpa->is_dummy) {
			continue;
		}
		if (from_up) {
			wp = r_list_get_n (r_graph_innodes (g->graph, vp), 0);
		} else {
			wp = r_graph_nth_neighbour (g->graph, vp, 0);
		}
		wpa = get_anode (wp);
		if (!wpa || !wpa->is_dummy) {
			continue;
		}
		if (vm) {
			int p = hash_get_int (P, wm);
			int k;

			for (k = wma->pos_in_layer + 1; k < wpa->pos_in_layer; k++) {
				const RGraphNode *w = g->layers[wma->layer].nodes[k];
				const RANode *aw = get_anode (w);
				if (aw && aw->is_dummy) {
					p &= hash_get_int (P, w);
				}
			}
			if (p) {
				hash_set (D, vm, from_up);
				for (k = vma->pos_in_layer + 1; k < vpa->pos_in_layer; k++) {
					const RGraphNode *v = g->layers[vma->layer].nodes[k];
					const RANode *av = get_anode (v);
					if (av && av->is_dummy) {
						hash_set (D, v, from_up);
					}
				}
			}
		}
		vm = vp;
		wm = wp;
		vma = get_anode (vm);
		wma = get_anode (wm);
	}
}

/* find a placement for a single node */
static void place_single(const RAGraph *g, int l, const RGraphNode *bm, const RGraphNode *bp, int from_up, int va) {
	const RGraphNode *gk, *v = g->layers[l].nodes[va];
	const RANode *ak;
	RANode *av = get_anode (v);
	if (!av) {
		return;
	}
	const RListIter *itk;

	const RList *neigh = from_up
		? r_graph_innodes (g->graph, v)
		: r_graph_get_neighbours (g->graph, v);

	int len = r_list_length (neigh);
	if (len == 0) {
		return;
	}

	int sum_x = 0;
	graph_foreach_anode (neigh, itk, gk, ak) {
		if (ak->is_reversed) {
			len--;
			continue;
		}
		sum_x += ak->x;
	}

	if (len == 0) {
		return;
	}
	if (av) {
		av->x = sum_x / len;
	}
	if (bm) {
		const RANode *bma = get_anode (bm);
		av->x = R_MAX (av->x, bma->x + dist_nodes (g, bm, v));
	}
	if (bp) {
		const RANode *bpa = get_anode (bp);
		av->x = R_MIN (av->x, bpa->x - dist_nodes (g, v, bp));
	}
}

static int RM_listcmp(const struct len_pos_t *a, const struct len_pos_t *b) {
	return (a->pos < b->pos) - (a->pos > b->pos);
}

static int RP_listcmp(const struct len_pos_t *a, const struct len_pos_t *b) {
	return (a->pos > b->pos) - (a->pos < b->pos);
}

static void collect_changes(const RAGraph *g, int l, const RGraphNode *b, int from_up, int s, int e, RList *list, int is_left) {
	const RGraphNode *vt = g->layers[l].nodes[e - 1];
	const RGraphNode *vtp = g->layers[l].nodes[s];
	struct len_pos_t *cx;
	int i;

	RListComparator lcmp = is_left? (RListComparator) RM_listcmp: (RListComparator) RP_listcmp;

	for (i = is_left? s: e - 1; (is_left && i < e) || (!is_left && i >= s); i = is_left? i + 1: i - 1) {
		const RGraphNode *v, *vi = g->layers[l].nodes[i];
		const RANode *av, *avi = get_anode (vi);
		const RList *neigh;
		const RListIter *it;
		int c = 0;

		if (!avi) {
			continue;
		}
		neigh = from_up
			? r_graph_innodes (g->graph, vi)
			: r_graph_get_neighbours (g->graph, vi);

		graph_foreach_anode (neigh, it, v, av) {
			if ((is_left && av->x >= avi->x) || (!is_left && av->x <= avi->x)) {
				c++;
			} else {
				cx = R_NEW (struct len_pos_t);
				c--;
				cx->len = 2;
				cx->pos = av->x;
				if (is_left) {
					cx->pos += dist_nodes (g, vi, vt);
				} else {
					cx->pos -= dist_nodes (g, vtp, vi);
				}
				r_list_add_sorted (list, cx, lcmp);
			}
		}

		cx = R_NEW0 (struct len_pos_t);
		cx->len = c;
		cx->pos = avi->x;
		if (is_left) {
			cx->pos += dist_nodes (g, vi, vt);
		} else {
			cx->pos -= dist_nodes (g, vtp, vi);
		}
		r_list_add_sorted (list, cx, lcmp);
	}

	if (b) {
		const RANode *ab = get_anode (b);
		cx = R_NEW (struct len_pos_t);
		if (cx) {
			cx->len = is_left? INT_MAX: INT_MIN;
			cx->pos = ab->x;
			if (is_left) {
				cx->pos += dist_nodes (g, b, vt);
			} else {
				cx->pos -= dist_nodes (g, vtp, b);
			}
			r_list_add_sorted (list, cx, lcmp);
		}
	}
}

static void combine_sequences(const RAGraph *g, int l, const RGraphNode *bm, const RGraphNode *bp, int from_up, int a, int r) {
	RList *Rm = r_list_new (), *Rp = r_list_new ();
	const RGraphNode *vt, *vtp;
	RANode *at, *atp;
	int rm, rp, t, m, i;
	Rm->free = (RListFree) free;
	Rp->free = (RListFree) free;

	t = (a + r) / 2;
	vt = g->layers[l].nodes[t - 1];
	vtp = g->layers[l].nodes[t];
	at = get_anode (vt);
	atp = get_anode (vtp);

	collect_changes (g, l, bm, from_up, a, t, Rm, true);
	collect_changes (g, l, bp, from_up, t, r, Rp, false);
	rm = rp = 0;

	m = dist_nodes (g, vt, vtp);
	if (at && atp) {
		while (atp->x - at->x < m) {
			if (atp->x == at->x) {
				int step = m / 2;
				at->x -= step;
				atp->x += m - step;
			} else {
				if (rm < rp) {
					if (r_list_empty (Rm)) {
						at->x = atp->x - m;
					} else {
						struct len_pos_t *cx = (struct len_pos_t *) r_list_pop (Rm);
						rm = rm + cx->len;
						at->x = R_MAX (cx->pos, atp->x - m);
						free (cx);
					}
				} else {
					if (r_list_empty (Rp)) {
						atp->x = at->x + m;
					} else {
						struct len_pos_t *cx = (struct len_pos_t *) r_list_pop (Rp);
						rp = rp + cx->len;
						atp->x = R_MIN (cx->pos, at->x + m);
						free (cx);
					}
				}
			}
		}
	}

	r_list_free (Rm);
	r_list_free (Rp);

	for (i = t - 2; i >= a; i--) {
		const RGraphNode *gv = g->layers[l].nodes[i];
		RANode *av = get_anode (gv);
		if (av && at) {
			av->x = R_MIN (av->x, at->x - dist_nodes (g, gv, vt));
		}
	}

	for (i = t + 1; i < r; i++) {
		const RGraphNode *gv = g->layers[l].nodes[i];
		RANode *av = get_anode (gv);
		if (av && atp) {
			av->x = R_MAX (av->x, atp->x + dist_nodes (g, vtp, gv));
		}
	}
}

/* places a sequence of consecutive original nodes */
/* it tries to minimize the distance between each node in the sequence and its
 * neighbours in the "previous" layer. Those neighbours are considered as
 * "fixed". The previous layer depends on the direction used during the layers
 * traversal */
static void place_sequence(const RAGraph *g, int l, const RGraphNode *bm, const RGraphNode *bp, int from_up, int va, int vr) {
	if (vr == va + 1) {
		place_single (g, l, bm, bp, from_up, va);
	} else if (vr > va + 1) {
		int vt = (vr + va) / 2;
		place_sequence (g, l, bm, bp, from_up, va, vt);
		place_sequence (g, l, bm, bp, from_up, vt, vr);
		combine_sequences (g, l, bm, bp, from_up, va, vr);
	}
}

/* finds the placements of nodes while traversing the graph in the given
 * direction */
/* places all the sequences of consecutive original nodes in each layer. */
static void original_traverse_l(const RAGraph *g, Sdb *D, Sdb *P, int from_up) {
	int i, k, va, vr;

	for (i = from_up? 0: g->n_layers - 1;
			(from_up && i < g->n_layers) || (!from_up && i >= 0);
			i = from_up? i + 1: i - 1) {
		int j;
		const RGraphNode *bm = NULL;
		const RANode *bma = NULL;

		j = 0;
		while (j < g->layers[i].n_nodes && !bm) {
			const RGraphNode *gn = g->layers[i].nodes[j];
			const RANode *an = get_anode (gn);
			if (an && an->is_dummy) {
				va = 0;
				vr = j;
				bm = gn;
				bma = an;
			}
			j++;
		}
		if (!bm) {
			va = 0;
			vr = g->layers[i].n_nodes;
		}
		place_sequence (g, i, NULL, bm, from_up, va, vr);
		for (k = va; k < vr - 1; k++) {
			set_dist_nodes (g, i, k, k + 1);
		}
		if (is_valid_pos (g, i, vr - 1) && bm) {
			set_dist_nodes (g, i, vr - 1, bma->pos_in_layer);
		}
		while (bm) {
			const RGraphNode *bp = get_right_dummy (g, bm);
			const RANode *bpa = NULL;
			bma = get_anode (bm);

			if (!bp) {
				va = bma->pos_in_layer + 1;
				vr = g->layers[bma->layer].n_nodes;
				place_sequence (g, i, bm, NULL, from_up, va, vr);
				for (k = va; k < vr - 1; k++) {
					set_dist_nodes (g, i, k, k + 1);
				}

				if (is_valid_pos (g, i, va)) {
					set_dist_nodes (g, i, bma->pos_in_layer, va);
				}
			} else if (hash_get_int (D, bm) == from_up) {
				bpa = get_anode (bp);
				va = bma->pos_in_layer + 1;
				vr = bpa->pos_in_layer;
				place_sequence (g, i, bm, bp, from_up, va, vr);
				hash_set (P, bm, true);
			}
			bm = bp;
		}
		adjust_directions (g, i, from_up, D, P);
	}
}

/* computes a final position of original nodes, considering dummies nodes as
 * fixed */
/* set the node placements traversing the graph downward and then upward */
static void place_original(RAGraph *g) {
	const RList *nodes = r_graph_get_nodes (g->graph);
	const RGraphNode *gn;
	const RListIter *itn;
	const RANode *an;

	Sdb *D = sdb_new0 ();
	if (!D) {
		return;
	}
	Sdb *P = sdb_new0 ();
	if (!P) {
		sdb_free (D);
		return;
	}
	g->dists = r_list_newf ((RListFree) free);
	if (!g->dists) {
		sdb_free (D);
		sdb_free (P);
		return;
	}

	graph_foreach_anode (nodes, itn, gn, an) {
		if (!an->is_dummy) {
			continue;
		}
		const RGraphNode *right_v = get_right_dummy (g, gn);
		const RANode *right = get_anode (right_v);
		if (right_v && right) {
			hash_set (D, gn, 0);
			int dt_eq = right->x - an->x == dist_nodes (g, gn, right_v);
			hash_set (P, gn, dt_eq);
		}
	}

	original_traverse_l (g, D, P, true);
	original_traverse_l (g, D, P, false);

	r_list_free (g->dists);
	g->dists = NULL;
	sdb_free (P);
	sdb_free (D);
}

static void aedge_free(AEdge *e) {
	if (e) {
		r_list_free (e->x);
		r_list_free (e->y);
		free (e);
	}
}

static void ranode_free(RANode *n) {
	if (n) {
		free (n->title);
		free (n->body);
		free (n);
	}
}

static void set_layer_gap(RAGraph *g) {
	int gap = 0;
	int i = 0, j = 0;
	RListIter *itn;
	RGraphNode *ga, *gb;
	RANode *a, *b;
	const RList *outnodes;

	g->layers[0].gap = 0;
	for (i = 0; i < g->n_layers; i++) {
		gap = 0;
		if (i + 1 < g->n_layers) {
			g->layers[i+1].gap = gap;
		}
		for (j = 0; j < g->layers[i].n_nodes; j++) {
			ga = g->layers[i].nodes[j];
			if (!ga) {
				continue;
			}
			a = (RANode *) ga->data;
			outnodes = ga->out_nodes;

			if (!outnodes || !a) {
				continue;
			}
			graph_foreach_anode (outnodes, itn, gb, b) {
				if (g->layout == 0) { // vertical layout
					if ((b->x != a->x) || b->layer <= a->layer) {
						gap += 1;
						if (b->layer <= a->layer) {
							g->layers[b->layer].gap += 1;
						}
					} else if ((!a->is_dummy && b->is_dummy) || (a->is_dummy && !b->is_dummy)) {
						gap += 1;
					}
				} else {
					if ((b->y == a->y && b->h != a->h) || b->y != a->y || b->layer <= a->layer) {
						gap += 1;
						if (b->layer <= a->layer) {
							g->layers[b->layer].gap += 1;
						}
					} else if ((!a->is_dummy && b->is_dummy) || (a->is_dummy && !b->is_dummy)) {
						gap += 1;
					}
				}
			}
		}
		if (i + 1 < g->n_layers) {
			g->layers[i+1].gap += gap;
		}
	}
}

static void fix_back_edge_dummy_nodes(RAGraph *g, RANode *from, RANode *to) {
	RANode *v, *tmp = NULL;
	RGraphNode *gv = NULL;
	RListIter *it;
	int i;
	r_return_if_fail (g && from && to);
	const RList *neighbours = r_graph_get_neighbours (g->graph, to->gnode);
	graph_foreach_anode (neighbours, it, gv, v) {
		tmp = v;
		while (tmp->is_dummy) {
			tmp = (RANode *) (((RGraphNode *)r_list_first (tmp->gnode->out_nodes))->data);
		}
		if (tmp->gnode->idx == from->gnode->idx) {
			break;
		}
		tmp = NULL;
	}
	if (tmp) {
		tmp = v;
		v = to;
		while (tmp->gnode->idx != from->gnode->idx) {
			v = tmp;
			tmp = (RANode *) (((RGraphNode *)r_list_first (v->gnode->out_nodes))->data);

			i = 0;
			while (v->gnode->idx != g->layers[v->layer].nodes[i]->idx) {
				i += 1;
			}

			while (i + 1 < g->layers[v->layer].n_nodes) {
				g->layers[v->layer].nodes[i] = g->layers[v->layer].nodes[i+1];
				i++;
			}
			g->layers[v->layer].nodes[g->layers[v->layer].n_nodes - 1] = 0;
			g->layers[v->layer].n_nodes -= 1;

			r_graph_del_node (g->graph, v->gnode);
			ranode_free (v);
		}
	}
}

static int get_edge_number(const RAGraph *g, RANode *src, RANode *dst, bool outgoing) {
	RListIter *itn;
	RGraphNode *gv;
	int cur_nth = 0;
	int nth = 0;
	RANode *v;

	if (outgoing && src->is_dummy) {
		if (src->gnode) {
			RANode *in = (RANode *) (((RGraphNode *)r_list_first ((src->gnode)->in_nodes))->data);
			cur_nth = get_edge_number (g, in, src, outgoing);
		}
	} else {
		const RList *neighbours = outgoing
			? r_graph_get_neighbours (g->graph, src->gnode)
			: r_graph_innodes (g->graph, dst->gnode);
		const int exit_edges = r_list_length (neighbours);
		graph_foreach_anode (neighbours, itn, gv, v) {
			cur_nth = nth;
			if (g->is_callgraph) {
				cur_nth = 0;
			} else if (exit_edges == 1) {
				cur_nth = -1;
			}
			if (outgoing && gv->idx == (dst->gnode)->idx) {
				break;
			}
			if (!outgoing && gv->idx == (src->gnode)->idx) {
				break;
			}
			nth++;
		}
	}
	return cur_nth;
}

static int count_edges(const RAGraph *g, RANode *src, RANode *dst) {
	return get_edge_number (g, src, dst, true);
}

static void backedge_info(RAGraph *g) {
	int i, j, k;
	int min, max;
	int inedge = 0;
	int outedge = 0;
	if (g->n_layers > ST16_MAX) {
		return;
	}

	int **arr = R_NEWS0 (int *, g->n_layers);
	if (!arr) {
		return;
	}
	for (i = 0; i < g->n_layers; i++) {
		arr[i] = R_NEWS0 (int, 2);
		if (!arr[i]) {
			goto err;
		}
	}

	for (i = 0; i < g->n_layers; i++) {
		for (j = 0; j < g->layers[i].n_nodes; j++) {
			RGraphNode *gt = g->layers[i].nodes[j];
			if (!gt) {
				continue;
			}
			RANode *t = (RANode *) gt->data;
			if (!t) {
				continue;
			}
			int tc = g->layout == 0 ? t->x : t->y;
			int tl = g->layout == 0 ? t->w : t->h;
			if (!j) {
				arr[i][0] = tc;
				arr[i][1] = tc + tl;
			}

			if (arr[i][0] > tc) {
				arr[i][0] = tc;
			}

			if (arr[i][1] < tc + tl) {
				arr[i][1] = tc + tl;
			}
		}

		for (j = 0; j < g->layers[i].n_nodes; j++) {
			RANode *a = get_anode (g->layers[i].nodes[j]);
			if (!a || a->is_dummy) {
				continue;
			}

			const RList *neighbours = r_graph_get_neighbours (g->graph, a->gnode);
			RGraphNode *gb;
			RANode *b;
			RListIter *itm;

			if (i == 0) {
				inedge += r_list_length (r_graph_innodes (g->graph, a->gnode));
			} else if (i == g->n_layers - 1) {
				outedge += r_list_length (neighbours);
			}

			graph_foreach_anode (neighbours, itm, gb, b) {
				if (b->layer > a->layer) {
					continue;
				}

				int nth = count_edges (g, a, b);
				int xinc = R_EDGES_X_INC + 2 * (nth + 1);

				int ax = g->layout == 0 ? a->x + xinc : a->y + (a->h / 2) + nth;
				int bx = g->layout == 0 ? b->x + xinc : b->y + (b->h / 2) + nth;

				if (g->layout == 0 && nth == 0 && bx > ax) {
					ax += 4;
				}

				min = arr[b->layer][0];
				max = arr[b->layer][1];
				for (k = b->layer; k <= a->layer; k++) {
					if (min > arr[k][0]) {
						min = arr[k][0];
					}

					if (max < arr[k][1]) {
						max = arr[k][1];
					}
				}

				int l = (ax - min) + (bx - min);
				int r = (max - ax) + (max - bx);

				for (k = b->layer; k <= a->layer; k++) {
					if (r < l) {
						arr[k][1] = max + 1;
					} else {
						arr[k][0] = min - 1;
					}
				}

				AEdge *e = R_NEW0 (AEdge);
				if (!e) {
					free (arr);
					return;
				}

				e->is_reversed = true;
				e->from = a;
				e->to = b;
				e->x = r_list_new ();
				e->y = r_list_new ();

				if (r < l) {
					r_list_append ((g->layout == 0 ? e->x : e->y), (void *) (size_t) (max + 1));
				} else {
					r_list_append ((g->layout == 0 ? e->x : e->y), (void *) (size_t) (min - 1));
				}

				r_list_append (g->edges, e);
			}
		}
	}

	//Assumption: layer layout is not changed w.r.t x-coordinate/y-coordinate for horizontal/vertical layout respectively.
	if (inedge) {
		RANode *n = (RANode *)g->layers[0].nodes[0]->data;
		AEdge *e = R_NEW0 (AEdge);
		if (!e) {
			free (arr);
			return;
		}
		e->is_reversed = true;
		e->from = NULL;
		e->to = NULL;
		e->x = r_list_new ();
		e->y = r_list_new ();
		if (g->layout == 0) {
			r_list_append (e->y, (void *) (size_t) (n->y - 1 - inedge));
		} else {
			r_list_append (e->x, (void *) (size_t) (n->x - 1 - inedge));
		}
		r_list_append (g->edges, e);
	}

	if (outedge) {
		RANode *n = (RANode *)g->layers[g->n_layers - 1].nodes[0]->data;
		AEdge *e = R_NEW0 (AEdge);
		if (!e) {
			free (arr);
			return;
		}

		e->is_reversed = true;
		e->from = NULL;
		e->to = NULL;
		e->x = r_list_new ();
		e->y = r_list_new ();
		if (g->layout == 0) {
			r_list_append (e->y, (void *) (size_t) (n->y + g->layers[g->n_layers - 1].height + 2 + outedge));
		} else {
			r_list_append (e->x, (void *) (size_t) (n->x + g->layers[g->n_layers - 1].width + 2 + outedge));
		}
		r_list_append (g->edges, e);
	}
 err:
	for (i = i - 1; i >= 0; i--) {
		free (arr[i]);
	}
	free (arr);
}

/* 1) trasform the graph into a DAG
 * 2) partition the nodes in layers
 * 3) split long edges that traverse multiple layers
 * 4) reorder nodes in each layer to reduce the number of edge crossing
 * 5) assign x and y coordinates to each node
 * 6) restore the original graph, with long edges and cycles */
static void set_layout(RAGraph *g) {
	int i, j, k;

	r_list_free (g->edges);
	g->edges = r_list_newf ((RListFree)aedge_free);

	remove_cycles (g);
	assign_layers (g);
	create_dummy_nodes (g);
	create_layers (g);
	minimize_crossings (g);

	if (r_cons_is_breaked ()) {
		r_cons_break_end ();
		return;
	}
	/* identify row height */
	for (i = 0; i < g->n_layers; i++) {
		int rh = 0;
		int rw = 0;
		for (j = 0; j < g->layers[i].n_nodes; j++) {
			const RANode *n = get_anode (g->layers[i].nodes[j]);
			if (n->h > rh) {
				rh = n->h;
			}
			if (n->w > rw) {
				rw = n->w;
			}
		}
		g->layers[i].height = rh;
		g->layers[i].width = rw;
	}

	for (i = 0; i < g->n_layers; i++) {
		for (j = 0; j < g->layers[i].n_nodes; j++) {
			RANode *a = (RANode *) g->layers[i].nodes[j]->data;
			if (a->is_dummy) {
				if (g->layout == 0) {
					a->h = g->layers[i].height;
				} else {
					a->w = g->layers[i].width;
				}
			}
			a->layer_height = g->layers[i].height;
			a->layer_width = g->layers[i].width;
		}
	}

	/* x-coordinate assignment: algorithm based on:
	 * A Fast Layout Algorithm for k-Level Graphs
	 * by C. Buchheim, M. Junger, S. Leipert */
	place_dummies (g);
	place_original (g);

	/* IDEA: need to put this hack because of the way algorithm is implemented.
	 * I think backedges should be restored to their original state instead of
	 * converting them to longedges and adding dummy nodes. */
	const RListIter *it;
	const RGraphEdge *e;
	r_list_foreach (g->back_edges, it, e) {
		RANode *from = e->from? get_anode (e->from): NULL;
		RANode *to = e->to? get_anode (e->to): NULL;
		fix_back_edge_dummy_nodes (g, from, to);
		r_agraph_del_edge (g, to, from);
		r_agraph_add_edge_at (g, from, to, e->nth);
	}

	switch (g->layout) {
	default:
	case 0: // vertical layout
		/* horizontal finalize x coordinate */
		for (i = 0; i < g->n_layers; i++) {
			for (j = 0; j < g->layers[i].n_nodes; j++) {
				RANode *n = get_anode (g->layers[i].nodes[j]);
				if (n) {
					n->x -= n->w / 2;
					if (g->is_tiny) {
						n->x /= 8;
					}
				}
			}
		}

		set_layer_gap (g);

		/* vertical align */
		for (i = 0; i < g->n_layers; i++) {
			int tmp_y = 0;
			tmp_y = g->layers[0].gap; //TODO: XXX: set properly
			for (k = 1; k <= i; k++) {
				tmp_y += g->layers[k-1].height + g->layers[k].gap + 3; //XXX: should be 4?
			}
			if (g->is_tiny) {
				tmp_y = i;
			}
			for (j = 0; j < g->layers[i].n_nodes; j++) {
				RANode *n = get_anode (g->layers[i].nodes[j]);
				if (n) {
					n->y = tmp_y;
				}
			}
		}
		break;
	/* experimental */
	case 1: // horizontal layout
		/* vertical y coordinate */
		for (i = 0; i < g->n_layers; i++) {
			for (j = 0; j < g->layers[i].n_nodes; j++) {
				RANode *n = get_anode (g->layers[i].nodes[j]);
				n->y = 1;
				for (k = 0; k < j; k++) {
					RANode *m = get_anode (g->layers[i].nodes[k]);
					n->y -= (m->h + VERTICAL_NODE_SPACING);
				}
			}
		}

		set_layer_gap (g);

		/* horizontal align */
		for (i = 0; i < g->n_layers; i++) {
			int xval = 1 + g->layers[0].gap + 1;
			for (k = 1; k <= i; k++) {
				xval += g->layers[k-1].width + g->layers[k].gap + 3;
			}
			for (j = 0; j < g->layers[i].n_nodes; j++) {
				RANode *n = get_anode (g->layers[i].nodes[j]);
				n->x = xval;
			}
		}
		break;
	}

	backedge_info (g);

	/* free all temporary structures used during layout */
	for (i = 0; i < g->n_layers; i++) {
		free (g->layers[i].nodes);
	}

	free (g->layers);
	r_list_free (g->long_edges);
	r_list_free (g->back_edges);
	r_cons_break_pop ();
}

static char *get_body(RCore *core, ut64 addr, int size, int opts) {
	char *body;
	RConfigHold *hc = r_config_hold_new (core->config);
	if (!hc) {
		return NULL;
	}
	r_config_hold (hc, "asm.lines", "asm.bytes", "asm.flags.inbytes",
		"asm.cmt.col", "asm.marks", "asm.offset",
		"asm.comments", "asm.cmt.right", "asm.lines.bb", NULL);
	const bool o_comments = r_config_get_b (core->config, "graph.comments");
	const bool o_cmtright = r_config_get_b (core->config, "graph.cmtright");
	const bool o_bytes = r_config_get_b (core->config, "graph.bytes");
	bool o_flags_in_bytes = r_config_get_b (core->config, "asm.flags.inbytes");
	const bool o_graph_offset = r_config_get_b (core->config, "graph.offset");
	int o_cursor = core->print->cur_enabled;
	int mw = r_config_get_i (core->config, "graph.bb.maxwidth");
	if (opts & BODY_COMMENTS) {
		r_core_visual_toggle_decompiler_disasm (core, true, false);
		char * res = r_core_cmd_strf (core, "pD %d @ 0x%08"PFMT64x, size, addr);
		res = r_str_replace (res, "; ", "", true);
		// res = r_str_replace (res, "\n", "(\n)", true);
		r_str_trim (res);
		res = r_str_trim_lines (res);
		if (mw > 0) {
			res = r_str_ansi_crop (res, 0, 0, mw, -1);
		}
		r_core_visual_toggle_decompiler_disasm (core, true, false);
		r_config_hold_restore (hc);
		r_config_hold_free (hc);
		return res;
	}

	// configure options
	if (r_config_get_b (core->config, "cfg.debug")) {
		r_config_set_b (core->config, "asm.flags.inbytes", true);
		o_flags_in_bytes = true;
	}
	r_config_set_b (core->config, "asm.lines.bb", false);
	r_config_set_b (core->config, "asm.lines", false);
	r_config_set_i (core->config, "asm.cmt.col", 0);
	r_config_set_b (core->config, "asm.marks", false);
	r_config_set_b (core->config, "asm.cmt.right", (opts & BODY_SUMMARY) || o_cmtright);
	r_config_set_b (core->config, "asm.comments", (opts & BODY_SUMMARY) || o_comments);
	r_config_set_b (core->config, "asm.bytes",
		(opts & (BODY_SUMMARY | BODY_OFFSETS)) || o_bytes || o_flags_in_bytes);
	r_config_set_b (core->config, "asm.bbmiddle", false);
	core->print->cur_enabled = false;

	const bool asm_offset = (opts & BODY_OFFSETS || opts & BODY_SUMMARY || o_graph_offset);
	r_config_set_b (core->config, "asm.offset", asm_offset);

	const bool html = r_config_get_b (core->config, "scr.html");
	r_config_set_b (core->config, "scr.html", false);

	const char *cmd = (opts & BODY_SUMMARY)? "pds": "pD";
	const char *bbcmd = r_config_get (core->config, "cmd.bbgraph");
	if (R_STR_ISNOTEMPTY (bbcmd)) {
		cmd = bbcmd;
	}
	if (r_config_get_b (core->config, "graph.aeab")) {
		body = r_core_cmd_strf (core, "%s 0x%08"PFMT64x, "aeab", addr);
	} else {
		body = r_core_cmd_strf (core, "%s %d @ 0x%08"PFMT64x, cmd, size, addr);
	}
	if (mw > 0) {
		body = r_str_ansi_crop (body, 0, 0, mw, -1);
	}
	r_config_set_i (core->config, "scr.html", html);
	// r_cons_canvas_bgfill (g->can, n->x, n->y, n->w, n->h, get_node_bgcolor (color, cur));
	// body = r_str_ansi_crop (body, 0, 0, 40, 20);
	// body = r_str_ansi_resetbg (body, Color_BGRED); // color);
	// r_str_ansi_filter (body, NULL, NULL, -1);
	// restore original options
	core->print->cur_enabled = o_cursor;
	r_config_hold_restore (hc);
	r_config_hold_free (hc);
	return body;
}

static char *get_bb_body(RCore *core, RAnalBlock *b, int opts, RAnalFunction *fcn, bool emu, ut64 saved_gp, ut8 *saved_arena, int saved_arena_size) {
	if (emu) {
		core->anal->gp = saved_gp;
		if (b->parent_reg_arena) {
			r_reg_arena_poke (core->anal->reg, b->parent_reg_arena, b->parent_reg_arena_size);
			R_FREE (b->parent_reg_arena);
			ut64 gp = r_reg_getv (core->anal->reg, "gp");
			if (gp) {
				core->anal->gp = gp;
			}
		} else {
			r_reg_arena_poke (core->anal->reg, saved_arena, saved_arena_size);
		}
	}
	if (b->parent_stackptr != INT_MAX) {
		core->anal->stackptr = b->parent_stackptr;
	}
	char *body = get_body (core, b->addr, b->size, opts);
	if (b->jump != UT64_MAX) {
		if (b->jump > b->addr) {
			RAnalBlock *jumpbb = r_anal_get_block_at (b->anal, b->jump);
			if (jumpbb && r_list_contains (jumpbb->fcns, fcn)) {
				if (emu && core->anal->last_disasm_reg && !jumpbb->parent_reg_arena) {
					jumpbb->parent_reg_arena = r_reg_arena_dup (core->anal->reg, core->anal->last_disasm_reg);
				}
				if (jumpbb->parent_stackptr == INT_MAX) {
					jumpbb->parent_stackptr = core->anal->stackptr + b->stackptr;
				}
			}
		}
	}
	if (b->fail != UT64_MAX) {
		if (b->fail > b->addr) {
			RAnalBlock *failbb = r_anal_get_block_at (b->anal, b->fail);
			if (failbb && r_list_contains (failbb->fcns, fcn)) {
				if (emu && core->anal->last_disasm_reg && !failbb->parent_reg_arena) {
					failbb->parent_reg_arena = r_reg_arena_dup (core->anal->reg, core->anal->last_disasm_reg);
				}
				if (failbb->parent_stackptr == INT_MAX) {
					failbb->parent_stackptr = core->anal->stackptr + b->stackptr;
				}
			}
		}
	}
	// body = r_str_ansi_resetbg (body, Color_BGRED); // color);
	// r_cons_canvas_bgfill (g->can, n->x, n->y, n->w, n->h, get_node_bgcolor (color, cur));
	return body;
}

static int bbcmp(RAnalBlock *a, RAnalBlock *b) {
	return a->addr - b->addr;
}

static void get_bbupdate(RAGraph *g, RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *iter;
	const bool emu = r_config_get_b (core->config, "asm.emu");
	ut64 saved_gp = core->anal->gp;
	ut8 *saved_arena = NULL;
	int saved_arena_size = 0;
	int saved_stackptr = core->anal->stackptr;
	char *shortcut = 0;
	int shortcuts = 0;
	core->keep_asmqjmps = false;

	if (emu) {
		saved_arena = r_reg_arena_peek (core->anal->reg, &saved_arena_size);
	}
	if (!fcn) {
		R_FREE (saved_arena);
		return;
	}
	if (fcn->bbs) {
		r_list_sort (fcn->bbs, (RListComparator) bbcmp);
	}

	shortcuts = r_config_get_b (core->config, "graph.nodejmps");
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}
		char *body = get_bb_body (core, bb, mode2opts (g), fcn, emu, saved_gp, saved_arena, saved_arena_size);
		char *title = get_title (bb->addr);

		// r_cons_canvas_bgfill (g->can, n->x, n->y, n->w, n->h, get_node_bgcolor (color, cur));
		if (shortcuts) {
			shortcut = r_core_add_asmqjmp (core, bb->addr);
			if (shortcut) {
				char *k = r_str_newf ("agraph.nodes.%s.shortcut", title);
				sdb_set (g->db, k, shortcut, 0);
				free (k);
				free (shortcut);
			}
		}
		RANode *node = r_agraph_get_node (g, title);
		if (node) {
			free (node->body);
			node->body = body;
			R_FREE (node->color);
			if (bb->color.r || bb->color.g || bb->color.b) {
				node->color = r_cons_rgb_str (NULL, -1, &bb->color);
			}
		} else {
			free (body);
		}
		free (title);
		core->keep_asmqjmps = true;
	}

	if (emu) {
		core->anal->gp = saved_gp;
		if (saved_arena) {
			r_reg_arena_poke (core->anal->reg, saved_arena, saved_arena_size);
			R_FREE (saved_arena);
		}
	}
	core->anal->stackptr = saved_stackptr;
}

static void fold_asm_trace(RCore *core, RAGraph *g) {
	const RList *nodes = r_graph_get_nodes (g->graph);
	RGraphNode *gn;
	RListIter *it;
	RANode *n;

	RANode *curnode = get_anode (g->curnode);
	graph_foreach_anode (nodes, it, gn, n) {
		if (curnode == n) {
			n->is_mini = false;
			g->need_reload_nodes = true;
			continue;
		}
		ut64 addr = r_num_get (NULL, n->title);
		RDebugTracepoint *tp = r_debug_trace_get (core->dbg, addr);
		n->is_mini = (tp == NULL);
	}
	g->need_update_dim = 1;
}

static void delete_dup_edges(RAGraph *g) {
	RListIter *it, *in_it, *in_it2, *in_it2_tmp;
	RGraphNode *n, *a, *b;
	r_list_foreach (g->graph->nodes, it, n) {
		r_list_foreach (n->out_nodes, in_it, a) {
			for (in_it2 = in_it->n; in_it2 && (b = in_it2->data, in_it2_tmp = in_it2->n, 1); in_it2 = in_it2_tmp) {
				if (a->idx == b->idx) {
					r_list_delete (n->out_nodes, in_it2);
					r_list_delete_data (n->all_neighbours, b);
					r_list_delete_data (b->in_nodes, n);
					r_list_delete_data (b->all_neighbours, n);
					g->graph->n_edges--;
				}
			}
		}
	}
}

static inline bool cur_points_to_bb(RAnalBlock *curbb, RAnalBlock *bb) {
	if (bb->addr == curbb->addr || bb->addr == curbb->jump || bb->addr == curbb->fail) {
		return true;
	}
	if (curbb->switch_op) {
		RListIter *it;
		RAnalCaseOp *cop;
		r_list_foreach (curbb->switch_op->cases, it, cop) {
			if (cop->addr == bb->addr) {
				return true;
			}
		}
	}
	return false;
}

static bool isbbfew(RAnalBlock *curbb, RAnalBlock *bb) {
	return cur_points_to_bb (curbb, bb) || cur_points_to_bb (bb, curbb);
}

static void add_child(RCore *core, RAGraph *g, RANode *u, ut64 jump) {
	if (jump == UT64_MAX) {
		return;
	}
	char *title = get_title (jump);
	RANode *v = r_agraph_get_node (g, title);
	if (v) {
		ut64 a = r_num_get (NULL, u->title);
		char key[64];
		const char *fmt = "agraph.edge.0x%" PFMT64x "_0x%" PFMT64x ".highlight";
		snprintf (key, sizeof (key), fmt, a, jump);
		bool hl = sdb_exists (core->sdb, key);
		r_agraph_add_edge (g, u, v, hl);
	} else {
		R_LOG_WARN ("Failed to add child node 0x%" PFMT64x " to %s, child not found", jump, u->title);
	}
	free (title);
}

/* build the RGraph inside the RAGraph g, starting from the Basic Blocks */
static int get_bbnodes(RAGraph *g, RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *iter;
	char *shortcut = NULL;
	int shortcuts = 0;
	bool emu = r_config_get_b (core->config, "asm.emu");
	bool few = r_config_get_b (core->config, "graph.few");
	int ret = false;
	ut64 saved_gp = core->anal->gp;
	int saved_arena_size = 0;
	ut8 *saved_arena = NULL;
	int saved_stackptr = core->anal->stackptr;
	core->keep_asmqjmps = false;

	if (!fcn) {
		return false;
	}
	if (emu) {
		saved_arena = r_reg_arena_peek (core->anal->reg, &saved_arena_size);
	}
	r_list_sort (fcn->bbs, (RListComparator) bbcmp);
	RAnalBlock *curbb = NULL;
	if (few) {
		r_list_foreach (fcn->bbs, iter, bb) {
			if (!curbb) {
				curbb = bb;
			}
			if (r_anal_block_contains (bb, core->offset)) {
				curbb = bb;
				break;
			}
		}
	}

	core->keep_asmqjmps = false;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}
		if (few && !isbbfew (curbb, bb)) {
			continue;
		}
		char *body = get_bb_body (core, bb, mode2opts (g), fcn, emu, saved_gp, saved_arena, saved_arena_size);
		char *title = get_title (bb->addr);
		char *color = (bb->color.r || bb->color.g || bb->color.b)? r_cons_rgb_str (NULL, -1, &bb->color): NULL;

		RANode *node = r_agraph_add_node (g, title, body, color);
		free (color);
		shortcuts = g->is_interactive ? r_config_get_b (core->config, "graph.nodejmps") : false;

		if (shortcuts) {
			shortcut = r_core_add_asmqjmp (core, bb->addr);
			if (shortcut) {
				char *k = r_str_newf ("agraph.nodes.%s.shortcut", title);
				sdb_set (g->db, k, shortcut, 0);
				free (k);
				free (shortcut);
			}
		}
		free (body);
		free (title);
		if (!node) {
			goto cleanup;
		}
		core->keep_asmqjmps = true;
	}

	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr == UT64_MAX) {
			continue;
		}
		if (few && !isbbfew (curbb, bb)) {
			continue;
		}

		char *title = get_title (bb->addr);
		RANode *u = r_agraph_get_node (g, title);
		free (title);
		add_child (core, g, u, bb->jump);
		add_child (core, g, u, bb->fail);
		if (bb->switch_op) {
			RListIter *it;
			RAnalCaseOp *cop;
			r_list_foreach (bb->switch_op->cases, it, cop) {
				add_child (core, g, u, cop->addr);
			}
		}
	}

	delete_dup_edges (g);
	ret = true;

cleanup:
	if (emu) {
		core->anal->gp = saved_gp;
		if (saved_arena) {
			r_reg_arena_poke (core->anal->reg, saved_arena, saved_arena_size);
			R_FREE (saved_arena);
		}
	}
	core->anal->stackptr = saved_stackptr;
	return ret;
}

/* build the RGraph inside the RAGraph g, starting from the Call Graph
 * information */
static bool get_cgnodes(RAGraph *g, RCore *core, RAnalFunction *fcn) {
	RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset, 0);
	if (!f) {
		return false;
	}
	if (!fcn) {
		fcn = f;
	}

	r_core_seek (core, f->addr, true);

	char *title = get_title (fcn->addr);
	RANode *fcn_anode = r_agraph_add_node (g, title, "", NULL);

	free (title);
	if (!fcn_anode) {
		return false;
	}

	fcn_anode->x = 10;
	fcn_anode->y = 3;

	RVecAnalRef *refs = r_anal_function_get_refs (fcn);
	if (refs) {
		RAnalRef *ref;
		R_VEC_FOREACH (refs, ref) {
			title = get_title (ref->addr);
			if (r_agraph_get_node (g, title)) {
				continue;
			}
			free (title);

			int size = 0;
			RAnalBlock *bb = r_anal_bb_from_offset (core->anal, ref->addr);
			if (bb) {
				size = bb->size;
			}

			char *body = get_body (core, ref->addr, size, mode2opts (g));
			title = get_title (ref->addr);

			RANode *node = r_agraph_add_node (g, title, body, NULL);
			if (!node) {
				RVecAnalRef_free (refs);
				return false;
			}

			free (title);
			free (body);

			node->x = 10;
			node->y = 10;

			r_agraph_add_edge (g, fcn_anode, node, false);
		}
	}

	RVecAnalRef_free (refs);
	return true;
}

static bool reload_nodes(RAGraph *g, RCore *core, RAnalFunction *fcn) {
	const bool is_c = g->is_callgraph;
	return is_c? get_cgnodes (g, core, fcn): get_bbnodes (g, core, fcn);
}

static void update_seek(RConsCanvas *can, RANode *n, int force) {
	if (!n) {
		return;
	}
	int x = n->x + can->sx;
	int y = n->y + can->sy;
	int w = can->w;
	int h = can->h;

	const bool doscroll = force || y < 0 || y + 5 > h || x + 5 > w || x + n->w + 5 < 0;
	if (doscroll) {
		if (n->w > w) { //too big for centering
			can->sx = -n->x;
		} else {
			can->sx = -n->x - n->w / 2 + w / 2;
		}
		if (n->h > h) { //too big for centering
			can->sy = -n->y;
		} else {
			can->sy = -n->y - n->h / 8 + h / 4;
		}
	}
}

static int is_near(const RANode *n, int x, int y, int is_next) {
	if (is_next) {
		return (n->y == y && n->x > x) || n->y > y;
	}
	return (n->y == y && n->x < x) || n->y < y;
}

/// XXX is wrong
static int is_near_h(const RANode *n, int x, int y, int is_next) {
	if (is_next) {
		return (n->x == x && n->y > y) || n->x > x;
	}
	return (n->x == x && n->y < y) || n->x < x;
}

static const RGraphNode *find_near_of(const RAGraph *g, const RGraphNode *cur, int is_next) {
	/* XXX: it's slow */
	const RList *nodes = r_graph_get_nodes (g->graph);
	const RListIter *it;
	const RGraphNode *gn, *resgn = NULL;
	const RANode *n, *acur = cur? get_anode (cur): NULL;
	const int default_v = is_next? INT_MIN: INT_MAX;
	const int start_x = acur? acur->x: default_v;
	const int start_y = acur? acur->y: default_v;

	graph_foreach_anode (nodes, it, gn, n) {
		// tab in horizontal layout is not correct, lets force vertical nextnode for now (g->layout == 0)
		bool isNear = true
			? is_near (n, start_x, start_y, is_next)
			: is_near_h (n, start_x, start_y, is_next);
		if (isNear) {
			const RANode *resn;

			if (!resgn) {
				resgn = gn;
				continue;
			}

			resn = get_anode (resgn);
			if ((is_next && resn->y > n->y) || (!is_next && resn->y < n->y)) {
				resgn = gn;
			} else if ((is_next && resn->y == n->y && resn->x > n->x)
					|| (!is_next && resn->y == n->y && resn->x < n->x)) {
				resgn = gn;
			}
		}
	}
	if (!resgn && cur) {
		resgn = find_near_of (g, NULL, is_next);
	}
	return resgn;
}

static void update_graph_sizes(RAGraph *g) {
	RListIter *it;
	RGraphNode *gk;
	RANode *ak, *min_gn, *max_gn;
	int max_x, max_y;
	int delta_x, delta_y;
	AEdge *e;

	g->x = g->y = INT_MAX;
	max_x = max_y = INT_MIN;
	min_gn = max_gn = NULL;

	graph_foreach_anode (r_graph_get_nodes (g->graph), it, gk, ak) {
		const RList *nd = NULL;
		int len;
		if (ak->x < g->x) {
			g->x = ak->x;
		}

		nd = r_graph_innodes (g->graph, gk);
		len = nd ? r_list_length (nd) + 1 : 0;
		if (ak->y - len < g->y) {
			g->y = ak->y - len;
			min_gn = ak;
		}

		if (ak->x + ak->w > max_x) {
			max_x = ak->x + ak->w;
		}

		nd = NULL;
		nd = r_graph_get_neighbours (g->graph, gk);
		len = nd ? r_list_length (nd) + 2 : 0;
		if (ak->y + ak->h + len > max_y) {
			max_y = ak->y + ak->h + len;
			max_gn = ak;
		}
	}
	/* while calculating the graph size, take into account long edges */
	r_list_foreach (g->edges, it, e) {
		RListIter *kt;
		void *vv;
		int v;
		if (r_cons_is_breaked ()) {
			break;
		}
		r_list_foreach (e->x, kt, vv) {
			v = (int) (size_t) vv;
			if (v < g->x) {
				g->x = v;
			}
			if (v + 1 > max_x) {
				max_x = v + 1;
			}
		}
		r_list_foreach (e->y, kt, vv) {
			v = (int) (size_t) vv;
			if (v < g->y) {
				g->y = v;
			}
			if (v + 1 > max_y) {
				max_y = v + 1;
			}
		}
	}
	r_cons_break_pop ();

	if (min_gn) {
		const RList *neigh = r_graph_innodes (g->graph, min_gn->gnode);
		if (r_list_length (neigh) > 0) {
			g->y--;
			max_y++;
		}
		if (max_gn) {
			const RList *neigh = r_graph_get_neighbours (g->graph, min_gn->gnode);
			if (r_list_length (neigh) > 0) {
				max_y++;
			}
		}
	}

	if (g->x != INT_MAX && g->y != INT_MAX) {
		g->w = max_x - g->x;
		if (g->title) {
			size_t len = strlen (g->title);
			if (len > INT_MAX) {
				g->w = INT_MAX;
			}
			if ((int) len > g->w) {
				g->w = len;
			}
		}
		g->h = max_y - g->y;
	} else {
		g->x = g->y = 0;
		g->w = g->h = 0;
	}

	sdb_num_set (g->db, "agraph.w", g->w, 0);
	sdb_num_set (g->db, "agraph.h", g->h, 0);
	/* delta_x, delta_y are needed to make every other x,y coordinates
	 * unsigned, so that we can use sdb_num_ API */
	delta_x = g->x < 0? -g->x: 0;
	delta_y = g->y < 0? -g->y: 0;
	sdb_num_set (g->db, "agraph.delta_x", delta_x, 0);
	sdb_num_set (g->db, "agraph.delta_y", delta_y, 0);
}

R_API void r_agraph_set_curnode(RAGraph *g, RANode *a) {
	if (!a) {
		return;
	}
	g->curnode = a->gnode;
	if (a->title) {
		sdb_set (g->db, "agraph.curnode", a->title, 0);
		if (g->on_curnode_change) {
			g->on_curnode_change (a, g->on_curnode_change_data);
		}
	}
}

static ut64 rebase(RAGraph *g, int v) {
	return g->x < 0? -g->x + v: v;
}

static void agraph_set_layout(RAGraph *g) {
	RListIter *it;
	RGraphNode *n;
	RANode *a;

	set_layout (g);

	update_graph_sizes (g);
	graph_foreach_anode (r_graph_get_nodes (g->graph), it, n, a) {
		if (a->is_dummy) {
			continue;
		}
		char *k = r_str_newf ("agraph.nodes.%s.x", a->title);
		sdb_num_set (g->db, k, rebase (g, a->x), 0);
		free (k);
		k = r_str_newf ("agraph.nodes.%s.y", a->title);
		sdb_num_set (g->db, k, rebase (g, a->y), 0);
		free (k);
		k = r_str_newf ("agraph.nodes.%s.w", a->title);
		sdb_num_set (g->db, k, a->w, 0);
		free (k);
		k = r_str_newf ("agraph.nodes.%s.h", a->title);
		sdb_num_set (g->db, k, a->h, 0);
		free (k);
	}
}

/* set the willing to center the screen on a particular node */
static void agraph_update_seek(RAGraph *g, RANode *n, bool force) {
	g->update_seek_on = n;
	g->force_update_seek = force;
}

static void agraph_print_node(const RAGraph *g, RANode *n) {
	if (n->is_dummy) {
		return;
	}
	const int cur = g->curnode && get_anode (g->curnode) == n;
	const bool isMini = is_mini (g);
	if (g->is_tiny) {
		tiny_RANode_print (g, n, cur);
	} else if (isMini || n->is_mini) {
		mini_RANode_print (g, n, cur, isMini);
	} else {
		normal_RANode_print (g, n, cur);
	}
}

static void agraph_print_nodes(const RAGraph *g) {
	const RList *nodes = r_graph_get_nodes (g->graph);
	RGraphNode *gn;
	RListIter *it;
	RANode *n;

	graph_foreach_anode (nodes, it, gn, n) {
		if (gn != g->curnode) {
			agraph_print_node (g, n);
		}
	}

	/* draw current node now to make it appear on top */
	if (g->curnode) {
		agraph_print_node (g, get_anode (g->curnode));
	}
}

struct tmplayer {
	int layer;
	int edgectr;
	int revedgectr;
	int minx;
	int maxx;
};
struct tmpbackedgeinfo {
	int ax;
	int ay;
	int bx;
	int by;
	int edgectr;
	int fromlayer;
	int tolayer;
	RCanvasLineStyle style;
};

int tmplayercmp (const void *a, const void *b) {
	return ((struct tmplayer *)a)->layer > ((struct tmplayer *)b)->layer;
}

static void agraph_print_edges_simple(RAGraph *g) {
	RCanvasLineStyle style = {0};
	RANode *n, *n2;
	RGraphNode *gn, *gn2;
	RListIter *iter, *iter2;
	const RList *nodes = r_graph_get_nodes (g->graph);
	graph_foreach_anode (nodes, iter, gn, n) {
		const RList *outnodes = n->gnode->out_nodes;
		graph_foreach_anode (outnodes, iter2, gn2, n2) {
			int sx = n->w / 2;
			int sy = n->h;
			int sx2 = n2->w / 2;
			if (g->is_tiny) {
				sx = 0;
				sy = 0;
				sx2 = 0;
			}
			// TODO: better alignments here
			r_cons_canvas_line (g->can,
				n->x + sx, n->y + sy,
				n2->x + sx2, n2->y, &style);

			if (n2->is_dummy) {
				r_cons_canvas_line (g->can,
					n2->x + sx2, n2->y - 1,
					n2->x + sx2, n2->y + n2->h, &style);
			}
		}
	}
}

static int first_x_cmp(const void *_a, const void *_b) {
	RGraphNode *ga = (RGraphNode *)_a;
	RGraphNode *gb = (RGraphNode *)_b;
	RANode *a = (RANode*) ga->data;
	RANode *b = (RANode*) gb->data;
	if (b->y < a->y) {
		return -1;
	}
	if (b->y > a->y) {
		return 1;
	}
	if (a->x < b->x) {
		return 1;
	}
	if (a->x > b->x) {
		return -1;
	}
	return 0;
}

static void agraph_print_edges(RAGraph *g) {
	if (!g->edgemode) {
		return;
	}
	if (g->edgemode == 1) {
		agraph_print_edges_simple (g);
		return;
	}
	int out_nth, in_nth, bendpoint;
	RListIter *itn, *itm, *ito;
	RCanvasLineStyle style = {0};
	const RList *nodes = r_graph_get_nodes (g->graph);
	RGraphNode *ga;
	RANode *a;

	RList *lyr = r_list_new ();
	RList *bckedges = r_list_new ();
	struct tmplayer *tl, *tm;

	graph_foreach_anode (nodes, itm, ga, a) {
		const RGraphNode *gb;
		RANode *b;
		RList *neighbours = (RList *)r_graph_get_neighbours (g->graph, ga);
		int ax, ay, bx, by, a_x_inc, b_x_inc;
		tl = tm = NULL;
		if (r_cons_is_breaked ()) {
			break;
		}

		r_list_foreach (lyr, ito, tl) {
			if (tl->layer == a->layer) {
				tm = tl;
				if (g->layout == 0) { //vertical layout
					if (tm->minx > a->x) {
						tm->minx = a->x;
					}
					if (tm->maxx < a->x + a->w) {
						tm->maxx = a->x + a->w;
					}
				} else {
					if (tm->minx > a->y) {
						tm->minx = a->y;
					}
					if (tm->maxx < a->y + a->h) {
						tm->maxx = a->y + a->h;
					}
				}
				break;
			}
		}

		if (!tm) {
			tm = R_NEW0 (struct tmplayer);
			if (tm) {
				tm->layer = a->layer;
				tm->edgectr = 0;
				tm->revedgectr = 0;
				if (g->layout == 0) { // vertical layout
					tm->minx = a->x;
					tm->maxx = a->x + a->w;
				} else {
					tm->minx = a->y;
					tm->maxx = a->y + a->h;
				}
				r_list_add_sorted (lyr, tm, tmplayercmp);
			}
		}

		bool many = r_list_length (neighbours) > 2;

		if (many && !g->is_callgraph) {
			ga->out_nodes->sorted = false;
			r_list_sort (neighbours, first_x_cmp);
		}

		graph_foreach_anode (neighbours, itn, gb, b) {
			out_nth = get_edge_number (g, a, b, true);
			in_nth = get_edge_number (g, a, b, false);

			bool parent_many = false;
			if (a->is_dummy) {
				RANode *in = (RANode *) (((RGraphNode *)r_list_first (ga->in_nodes))->data);
				while (in && in->is_dummy) {
					in = (RANode *) (((RGraphNode *)r_list_first ((in->gnode)->in_nodes))->data);
				}
				if (in && in->gnode) {
					parent_many = r_list_length (in->gnode->out_nodes) > 2;
				} else {
					parent_many = false;
				}
			}

			style.dot_style = DOT_STYLE_NORMAL;
			if (many || parent_many) {
				style.color = LINE_UNCJMP;
			} else {
				switch (out_nth) {
				case 0:
					style.color = LINE_TRUE;
					style.dot_style = DOT_STYLE_CONDITIONAL;
					break;
				case 1:
					style.color = LINE_FALSE;
					style.dot_style = DOT_STYLE_CONDITIONAL;
					break;
				case -1:
					style.color = LINE_UNCJMP;
					break;
				default:
					style.color = LINE_NONE;
					break;
				}
			}
			if (!R_STR_ISEMPTY (a->title) && !R_STR_ISEMPTY (b->title)) {
				ut64 aa = r_num_get (NULL, a->title);
				ut64 bb = r_num_get (NULL, b->title);
				r_strf_var (k, 64, "agraph.edge.0x%"PFMT64x"_0x%"PFMT64x".highlight", aa, bb);
				if (sdb_exists (g->db, k)) {
					style.ansicolor = Color_BYELLOW; // it's CYAN for graphviz
				} else {
					style.ansicolor = NULL;
				}
			}
			switch (g->layout) {
			case 0:
			default:
				style.symbol = (!g->hints || a->is_dummy) ? LINE_NOSYM_VERT : style.color;
				if (a->y + a->h > b->y) {
					style.dot_style = DOT_STYLE_BACKEDGE;
				}

				a_x_inc = R_EDGES_X_INC + 2 * (out_nth + 1);
				b_x_inc = R_EDGES_X_INC + 2 * (in_nth + 1);

				bx = b->is_dummy ? b->x : (b->x + b_x_inc);
				ay = a->y + a->h;
				by = b->y - 1;

				if (many && !g->is_callgraph) {
					int t = R_EDGES_X_INC + 2 * (neighbours->length + 1);
					ax = a->is_dummy ? a->x : (a->x + a->w/2 + (t/2 - a_x_inc));
					bendpoint = bx < ax ? neighbours->length - out_nth :  out_nth;
				} else {
					ax = a->is_dummy ? a->x : (a->x + a_x_inc);
					bendpoint = tm->edgectr;
				}

				if (!a->is_dummy && itn == neighbours->head && out_nth == 0 && bx > ax) {
					ax += (many && !g->is_callgraph) ? 0 : 4;
				}
				if (a->h < a->layer_height) {
					r_cons_canvas_line (g->can, ax, ay, ax, ay + a->layer_height - a->h, &style);
					ay = a->y + a->layer_height;
					style.symbol = LINE_NOSYM_VERT;
				}
				if (by >= ay) {
					r_cons_canvas_line_square_defined (g->can, ax, ay, bx, by, &style, bendpoint, true);
				} else {
					struct tmpbackedgeinfo *tmp = calloc (1, sizeof (struct tmpbackedgeinfo));
					tmp->ax = ax;
					tmp->bx = bx;
					tmp->ay = ay;
					tmp->by = by;
					tmp->edgectr = bendpoint;
					tmp->fromlayer = a->layer;
					tmp->tolayer = b->layer;
					tmp->style = style;
					r_list_append (bckedges, tmp);
				}
				if (b->is_dummy) {
					style.symbol = LINE_NOSYM_VERT;
					r_cons_canvas_line (g->can, bx, by, bx, b->y + b->h, &style);
				}
				if (b->x != a->x || b->layer <= a->layer || (!a->is_dummy && b->is_dummy) || (a->is_dummy && !b->is_dummy)) {
					if (tm) {
						tm->edgectr++;
					}
				}
				break;
			case 1:
				style.symbol = (!g->hints || a->is_dummy) ? LINE_NOSYM_HORIZ : style.color;
				if (a->x + a->w > b->x) {
					style.dot_style = DOT_STYLE_BACKEDGE;
				}

				ax = a->x;
				if (g->zoom > 0) {
					ax += a->w;
				} else {
					ax ++;
				}
				ay = a->y;
				if (!a->is_dummy && g->zoom > 0) {
					ay += R_EDGES_X_INC + out_nth;
				}
				bx = b->x - 1;
				by = b->y;
				if (!b->is_dummy && g->zoom > 0) {
					by += R_EDGES_X_INC + out_nth;
				}

				if (a->w < a->layer_width) {
					r_cons_canvas_line_square_defined (g->can, ax, ay, a->x + a->layer_width, ay, &style, 0, false);
					ax = a->x;
					if (g->zoom > 1) {
						ax += a->layer_width;
					} else {
						ax += 1;
					}
					style.symbol = LINE_NOSYM_HORIZ;
				}
				if (bx >= ax) {
					r_cons_canvas_line_square_defined (g->can, ax, ay, bx, by, &style, tm->edgectr, false);
				} else {
					struct tmpbackedgeinfo *tmp = calloc (1, sizeof (struct tmpbackedgeinfo));
					if (tmp) {
						tmp->ax = ax;
						tmp->bx = bx;
						tmp->ay = ay;
						tmp->by = by;
						tmp->edgectr = tm->edgectr;
						tmp->fromlayer = a->layer;
						tmp->tolayer = b->layer;
						tmp->style = style;
						r_list_append (bckedges, tmp);
					}
				}
				if (b->is_dummy) {
					style.symbol = LINE_NOSYM_HORIZ;
					r_cons_canvas_line_square_defined (g->can, bx, by, bx + b->layer_width, by, &style, 0, false);
				}
				if ((b->y == a->y && b->h != a->h) || b->y != a->y || b->layer <= a->layer || (!a->is_dummy && b->is_dummy) || (a->is_dummy && !b->is_dummy)) {
					tm->edgectr += 1;
				}
				break;
			}
		}
	}

	struct tmpbackedgeinfo *temp;
	r_list_foreach (bckedges, itm, temp) {
		int leftlen, rightlen;
		int minx = 0, maxx = 0;
		struct tmplayer *tt = NULL;
		tl = r_list_get_n (lyr, temp->fromlayer);
		if (r_cons_is_breaked ()) {
			break;
		}

		r_list_foreach (lyr, ito, tl) {
			if (tl->layer <= temp->tolayer) {
				tt = tl;
				minx = tl->minx;
				maxx = tl->maxx;
				continue;
			}
			minx = minx < tl->minx ? minx : tl->minx;
			maxx = maxx > tl->maxx ? maxx : tl->maxx;
			if (tl->layer >= temp->fromlayer) {
				break;
			}
		}

		if (tt) {
			tt->revedgectr += 1;
		}
		if (g->layout == 0) {
			leftlen = (temp->ax - minx) + (temp->bx - minx);
			rightlen = (maxx - temp->ax) + (maxx - temp->bx);
		} else {
			leftlen = (temp->ay - minx) + (temp->by - minx);
			rightlen = (maxx - temp->ay) + (maxx - temp->by);
		}

		if (tt) {
			int arg = (rightlen < leftlen)? maxx + 1: minx - 1;
			r_cons_canvas_line_back_edge (g->can, temp->ax, temp->ay, temp->bx, temp->by,
					&(temp->style), temp->edgectr, arg, tt->revedgectr, !g->layout);
		}

		r_list_foreach (lyr, ito, tl) {
			if (tl->layer < temp->tolayer) {
				continue;
			}
			if (rightlen < leftlen) {
				tl->maxx = maxx + 1;
			} else {
				tl->minx = minx - 1;
			}
			if (tl->layer >= temp->fromlayer) {
				break;
			}
		}
	}

	r_list_foreach (lyr, ito, tl) {
		free (tl);
	}

	r_list_foreach (bckedges, ito, tl) {
		free (tl);
	}

	r_list_free (lyr);
	r_list_free (bckedges);
	r_cons_break_pop ();
}

static void agraph_toggle_callgraph(RAGraph *g) {
	g->is_callgraph = !g->is_callgraph;
	g->need_reload_nodes = true;
	g->force_update_seek = true;
}

static void agraph_set_zoom(RAGraph *g, int v) {
	if (v >= -10) {
		g->is_tiny = false;
		if (v == 0) {
			g->mode = R_AGRAPH_MODE_MINI;
		} else if (v < 0) {
			g->mode = R_AGRAPH_MODE_TINY;
			g->is_tiny = true;
		} else {
			g->mode = R_AGRAPH_MODE_NORMAL;
		}
		const int K = 920;
		if (g->zoom < v) {
			g->can->sy = (g->can->sy * K) / 1000;
		} else {
			g->can->sy = (g->can->sy * 1000) / K;
		}
		g->zoom = v;
		g->need_update_dim = true;
		g->need_set_layout = true;
	}
}

/* reload all the info in the nodes, depending on the type of the graph
 * (callgraph, CFG, etc.), set the default layout for these nodes and center
 * the screen on the selected one */
static bool agraph_reload_nodes(RAGraph *g, RCore *core, RAnalFunction *fcn) {
	if (g->is_handmade) {
		return true;
	}
	r_agraph_reset (g);
	return reload_nodes (g, core, fcn);
}

static void follow_nth(RAGraph *g, int nth) {
	const RGraphNode *cn = r_graph_nth_neighbour (g->graph, g->curnode, nth);
	RANode *a = get_anode (cn);

	while (a && a->is_dummy) {
		cn = r_graph_nth_neighbour (g->graph, a->gnode, 0);
		a = get_anode (cn);
	}
	if (a) {
		r_agraph_set_curnode (g, a);
	}
}

static void move_current_node(RAGraph *g, int xdiff, int ydiff) {
	RANode *n = get_anode (g->curnode);
	if (n) {
		if (is_tiny (g)) {
			xdiff = NORMALIZE_MOV (xdiff);
			ydiff = NORMALIZE_MOV (ydiff);
		}
		n->x += xdiff;
		n->y += ydiff;
	}
}

static void agraph_toggle_tiny(RAGraph *g) {
	g->is_tiny = !g->is_tiny;
	g->need_update_dim = 1;
	agraph_refresh (r_cons_singleton ()->event_data);
	agraph_set_layout ((RAGraph *) g);
}

static void agraph_toggle_mini(RAGraph *g) {
	RANode *n = get_anode (g->curnode);
	if (n) {
		n->is_mini = !n->is_mini;
	}
	g->need_update_dim = 1;
	agraph_refresh (r_cons_singleton ()->event_data);
	agraph_set_layout ((RAGraph *) g);
}

static void agraph_follow_innodes(RAGraph *g, bool in) {
	int count = 0;
	RListIter *iter;
	RANode *an = get_anode (g->curnode);
	if (!an) {
		return;
	}
	const RList *list = in? an->gnode->in_nodes: an->gnode->out_nodes;
	int nth = -1;
	if (r_list_length (list) == 0) {
		return;
	}
	r_cons_gotoxy (0, 2);
	r_cons_printf (in? "Input nodes:\n": "Output nodes:\n");
	RList *options = r_list_newf (NULL);
	RList *gnodes = in? an->gnode->in_nodes: an->gnode->out_nodes;
	RGraphNode *gn;
	r_list_foreach (gnodes, iter, gn) {
		RANode *an = get_anode (gn);
		RGraphNode *gnn = agraph_get_title (g, an, in);
		if (gnn) {
			RANode *nnn = gnn->data;
			RANode *o;
			RListIter *iter2;
			// avoid dupes
			r_list_foreach (options, iter2, o) {
				if (!strcmp (o->title, nnn->title)) {
					continue;
				}
			}
			r_cons_printf ("%d %s\n", count, nnn->title);
			r_list_append (options, nnn);
			count++;
		}
	}
	r_cons_flush ();
	if (r_list_length (list) == 1) {
		nth = 0;
	} else if (r_list_length (list) < 10) {
		// just 1 key
		r_cons_set_raw (true);
		char ch = r_cons_readchar ();
		if (ch >= '0' && ch <= '9') {
			nth =  ch - '0';
		}
	} else {
		r_cons_show_cursor (true);
		r_cons_enable_mouse (false);
		char *nth_string = r_cons_input ("index> ");
		nth = atoi (nth_string);
		if (nth == 0 && *nth_string != '0') {
			nth = -1;
		}
		free (nth_string);
	}
	if (nth != -1) {
		RANode *selected_node = r_list_get_n (options, nth);
		r_agraph_set_curnode (g, selected_node);
	}
	r_list_free (options);
	agraph_update_seek (g, get_anode (g->curnode), false);
}

static void agraph_follow_true(RAGraph *g) {
	follow_nth (g, 0);
	agraph_update_seek (g, get_anode (g->curnode), false);
}

static void agraph_follow_false(RAGraph *g) {
	follow_nth (g, 1);
	agraph_update_seek (g, get_anode (g->curnode), false);
}

/* seek the next node in visual order */
static void agraph_next_node(RAGraph *g) {
	RANode *a = get_anode (find_near_of (g, g->curnode, true));
	while (a && a->is_dummy) {
		a = get_anode (find_near_of (g, a->gnode, true));
	}
	r_agraph_set_curnode (g, a);
	agraph_update_seek (g, get_anode (g->curnode), false);
}

/* seek the previous node in visual order */
static void agraph_prev_node(RAGraph *g) {
	RANode *a = get_anode (find_near_of (g, g->curnode, false));
	while (a && a->is_dummy) {
		a = get_anode (find_near_of (g, a->gnode, false));
	}
	r_agraph_set_curnode (g, a);
	agraph_update_seek (g, get_anode (g->curnode), false);
}

static void agraph_update_title(RCore *core, RAGraph *g, RAnalFunction *fcn) {
	RANode *a = get_anode (g->curnode);
	if (!a) {
		return;
	}
	eprintf ("GET NODE %p\n", a);
	char *sig = r_core_cmd_str (core, "afcf");
	char *new_title = r_str_newf (
		"%s[0x%08"PFMT64x "]> %s # %s ",
		core->visual.graphCursor? "(cursor)": "",
		fcn->addr, a? a->title: "", sig);
	r_agraph_set_title (g, new_title);
	free (new_title);
	free (sig);
}

/* look for any change in the state of the graph and update what's necessary */
static bool check_changes(RAGraph *g, bool is_interactive, RCore *core, RAnalFunction *fcn) {
	int oldpos[2] = {
		0, 0
	};
	if (g->update_seek_on && core && r_config_get_b (core->config, "graph.few")) {
		g->need_reload_nodes = true;
	}
	if (g->need_reload_nodes && core) {
		if (!g->update_seek_on && !g->force_update_seek) {
			// save scroll here
			oldpos[0] = g->can->sx;
			oldpos[1] = g->can->sy;
		}
		if (!agraph_reload_nodes (g, core, fcn)) {
			return false;
		}
	}
	if (core && core->config) {
		if (r_config_get_b (core->config, "graph.trace")) {
			// fold all bbs not traced
			fold_asm_trace (core, g);
		}
	}
	g->bb_maxwidth = core? r_config_get_i (core->config, "graph.bb.maxwidth"): 0;
	if (g->need_update_dim || g->need_reload_nodes || !is_interactive) {
		update_node_dimension (g->graph, is_mini (g), g->zoom, g->edgemode, g->is_callgraph, g->layout);
	}
	if (g->need_set_layout || g->need_reload_nodes || !is_interactive) {
		agraph_set_layout (g);
	}
	if (core) {
		ut64 off = r_anal_get_bbaddr (core->anal, core->offset);
		if (off != UT64_MAX) {
			char *title = get_title (off);
			RANode *cur_anode = get_anode (g->curnode);
			if (fcn && ((is_interactive && !cur_anode) || (cur_anode && strcmp (cur_anode->title, title)))) {
				g->update_seek_on = r_agraph_get_node (g, title);
				if (g->update_seek_on) {
					r_agraph_set_curnode (g, g->update_seek_on);
					g->force_update_seek = true;
				}
			}
			free (title);
		}
		g->can->color = r_config_get_i (core->config, "scr.color");
		g->hints = r_config_get_b (core->config, "graph.hints");
	}
	if (g->update_seek_on || g->force_update_seek) {
		RANode *n = g->update_seek_on;
		if (!n && g->curnode) {
			n = get_anode (g->curnode);
		}
		if (n) {
			update_seek (g->can, n, g->force_update_seek);
		}
	}
	if (fcn) {
		agraph_update_title (core, g, fcn);
	}
	if (oldpos[0] || oldpos[1]) {
		g->can->sx = oldpos[0];
		g->can->sy = oldpos[1];
	}
	g->need_reload_nodes = false;
	g->need_update_dim = false;
	g->need_set_layout = false;
	g->update_seek_on = NULL;
	g->force_update_seek = false;
	return true;
}

static int agraph_print(RAGraph *g, bool is_interactive, RCore *core, RAnalFunction *fcn) {
	int h, w = r_cons_get_size (&h);
	bool ret = check_changes (g, is_interactive, core, fcn);
	if (!ret) {
		return false;
	}

	if (is_interactive) {
		r_cons_clear00 ();
	} else {
		/* TODO: limit to screen size when the output is not redirected to file */
		update_graph_sizes (g);
	}

	h = is_interactive? h: g->h + 1;
	w = is_interactive? w: g->w + 2;
	if (!r_cons_canvas_resize (g->can, w, h)) {
		return false;
	}
	// r_cons_canvas_clear (g->can);
	if (!is_interactive) {
		g->can->sx = -g->x;
		g->can->sy = -g->y - 1;
	}
	if (g->is_dis) {
		(void) G (-g->can->sx + 1, -g->can->sy + 2);
		bool scr_utf8 = r_config_get_b (core->config, "scr.utf8");
		bool asm_bytes = r_config_get_b (core->config, "asm.bytes");
		bool asm_cmt_right = r_config_get_b (core->config, "asm.cmt.right");
		r_config_set_b (core->config, "scr.utf8", false);
		r_config_set_b (core->config, "asm.bytes", false);
		r_config_set_b (core->config, "asm.cmt.right", false);
		char *str = r_core_cmd_str (core, "pd $r");
		if (str) {
			W (str);
			free (str);
		}
		r_config_set_b (core->config, "scr.utf8", scr_utf8);
		r_config_set_b (core->config, "asm.bytes", asm_bytes);
		r_config_set_b (core->config, "asm.cmt.right", asm_cmt_right);
	}
	if (R_STR_ISNOTEMPTY (g->title)) {
		g->can->sy++;
	}
	agraph_print_edges (g);
	agraph_print_nodes (g);
	if (R_STR_ISNOTEMPTY (g->title)) {
		g->can->sy--;
	}
	/* print the graph title */
	(void) G (-g->can->sx, -g->can->sy);
	if (!g->is_tiny) {
		int color = core? r_config_get_i (core->config, "scr.color"): 0;
		if (color > 0) {
			const char *kolor = core->cons->context->pal.prompt;
			r_cons_gotoxy (0, 0);
			r_cons_print (kolor?kolor: Color_WHITE);
			r_cons_print (g->title);
			r_cons_print (Color_RESET"\r");
		} else {
			W (g->title); // canvas write is always black/white
		// 	r_cons_print (g->title);
		}
	}
	if (is_interactive && g->title) {
		int title_len = strlen (g->title);
		r_cons_canvas_fill (g->can, -g->can->sx + title_len, -g->can->sy,
			w - title_len, 1, ' ');
	}

	r_cons_canvas_print_region (g->can);

	if (is_interactive) {
		r_cons_newline ();
		const char *cmdv = r_config_get (core->config, "cmd.gprompt");
		bool mustFlush = false;
		r_cons_visual_flush ();
		if (!strcmp (cmdv, ".dr*")) {
			cmdv = ".dr*;dr=@e:hex.cols=`?v $w*3`";
		}
		if (R_STR_ISNOTEMPTY (cmdv)) {
			r_cons_gotoxy (0, 2);
			r_cons_print (Color_RESET);
			r_core_cmd0 (core, cmdv);
			mustFlush = true;
		}
		if (core && core->scr_gadgets) {
			r_core_cmd_call (core, "pg");
		}
		if (mustFlush) {
			r_cons_flush ();
		}
		if (r_config_get_b (core->config, "graph.mini")) { // minigraph
			int h, w = r_cons_get_size (&h);
			r_cons_push ();
			g->can->h *= 4;
			RConsCanvas *_can = g->can;
			g->can = r_cons_canvas_new (w * 2, h * 4);
			g->can->sx = _can->sx;
			g->can->sy = _can->sy;
			g->can->color = 0;
			g->can->linemode = _can->linemode;
			agraph_print_edges (g);
			agraph_print_nodes (g);
			r_cons_canvas_print_region (g->can);
			g->can = _can;
			char *s = strdup (r_cons_singleton ()->context->buffer);
			r_cons_pop ();
			cmd_agfb3 (core, s, w - 40, 2);
			free (s);
			g->can->h /= 4;
			r_cons_flush ();
		}
	}

	return true;
}

static void check_function_modified(RCore *core, RAnalFunction *fcn) {
	if (r_anal_function_was_modified (fcn)) {
		if (r_config_get_b (core->config, "anal.onchange")
			|| r_cons_yesno ('y', "Function was modified. Reanalyze? (Y/n)")) {
			r_anal_function_update_analysis (fcn);
		}
	}
}

static int agraph_refresh(struct agraph_refresh_data *grd) {
	if (!grd) {
		return 0;
	}
	r_cons_singleton ()->event_data = grd;
	RCore *core = grd->core;
	RAGraph *g = grd->g;
	RAnalFunction *f = NULL;
	RAnalFunction **fcn = grd->fcn;
	if (!fcn) {
		return agraph_print (g, grd->fs, core, NULL);
	}
	// allow to change the current function during debugging
	if (g->is_instep && r_config_get_b (core->config, "cfg.debug")) {
		// seek only when the graph node changes
		const char *pc = r_reg_get_name (core->dbg->reg, R_REG_NAME_PC);
		ut64 addr = r_reg_getv (core->dbg->reg, pc);
		RANode *acur = get_anode (g->curnode);

		addr = r_anal_get_bbaddr (core->anal, addr);
		char *title = get_title (addr);
		if (!acur || strcmp (acur->title, title)) {
			r_core_cmd_call (core, "sr PC");
		}
		free (title);
		g->is_instep = false;
	}

	if (grd->follow_offset) {
		if (r_io_is_valid_offset (core->io, core->offset, 0)) {
			f = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (!f) {
				if (!g->is_dis) {
					if (!r_cons_yesno ('y', "\rNo function at 0x%08"PFMT64x". Define it here (Y/n)? ", core->offset)) {
						return 0;
					}
					r_core_cmd_call (core, "af");
				}
				f = r_anal_get_fcn_in (core->anal, core->offset, 0);
				g->need_reload_nodes = true;
			}
			if (f && fcn && f != *fcn) {
				*fcn = f;
				check_function_modified (core, *fcn);
				g->need_reload_nodes = true;
				if (!core->visual.coming_from_vmark) {
					g->force_update_seek = true;
					core->visual.coming_from_vmark = false;
				}
			}
		} else {
			// TODO: maybe go back to avoid seeking from graph view to an scary place?
			r_cons_message ("This is not a valid offset\n");
			r_cons_flush ();
		}
	}

	int res = agraph_print (g, grd->fs, core, *fcn);

	if (r_config_get_b (core->config, "scr.scrollbar")) {
		r_core_print_scrollbar (core);
	}

	return res;
}

static void agraph_refresh_oneshot(struct agraph_refresh_data *grd) {
	r_core_task_enqueue_oneshot (&grd->core->tasks, (RCoreTaskOneShot) agraph_refresh, grd);
}

static void agraph_set_need_reload_nodes(struct agraph_refresh_data *grd) {
	grd->g->need_reload_nodes = true;
}

static void agraph_toggle_speed(RAGraph *g, RCore *core) {
	const int alt = r_config_get_b (core->config, "graph.scroll");
	g->movspeed = g->movspeed == DEFAULT_SPEED? alt: DEFAULT_SPEED;
}

static void agraph_init(RAGraph *g) {
	g->is_callgraph = false;
	g->is_instep = false;
	g->need_reload_nodes = true;
	g->show_node_titles = true;
	g->show_node_body = true;
	g->force_update_seek = true;
	g->graph = r_graph_new ();
	g->nodes = sdb_new0 ();
	g->edgemode = 2;
	g->zoom = ZOOM_DEFAULT;
	g->hints = 1;
	g->movspeed = DEFAULT_SPEED;
	g->db = sdb_new0 ();
	r_vector_init (&g->ghits.word_list, sizeof (struct r_agraph_location), NULL, NULL);
}

static void graphNodeMove(RAGraph *g, int dir, int speed) {
	int delta = (dir == 'k')? -1: 1;
	if (dir == 'H') {
		return;
	}
	if (dir == 'h' || dir == 'l') {
		// horizontal scroll
		if (is_mini (g)) {
			g->discroll = 0;
		} else {
			int delta = (dir == 'l')? 1: -1;
			move_current_node (g, speed * delta, 0);
		}
	} else {
		// vertical scroll
		if (is_mini (g)) {
			g->discroll += (delta * speed);
		} else if (g->is_dis) {
			// XXX core is null here cant work
			// RCore *core = NULL;
			// r_core_cmdf (core, "so %d", (delta * 4) * speed);
		} else {
			move_current_node (g, 0, delta * speed);
		}
	}
}

static void agraph_free_nodes(RAGraph *g) {
	RListIter *it;
	RGraphNode *n;
	RANode *a;

	graph_foreach_anode (r_graph_get_nodes (g->graph), it, n, a) {
		ranode_free (a);
	}

	sdb_free (g->nodes);
}

static void sdb_set_enc(Sdb *db, const char *key, const char *v, ut32 cas) {
	char *estr = sdb_encode ((const void *) v, -1);
	sdb_set (db, key, estr, cas);
	free (estr);
}

static void agraph_sdb_init(const RAGraph *g) {
	sdb_bool_set (g->db, "agraph.is_callgraph", g->is_callgraph, 0);
	RCons *cons = r_cons_singleton ();
	sdb_set_enc (g->db, "agraph.color_box", cons->context->pal.graph_box, 0);
	sdb_set_enc (g->db, "agraph.color_box2", cons->context->pal.graph_box2, 0);
	sdb_set_enc (g->db, "agraph.color_box3", cons->context->pal.graph_box3, 0);
	sdb_set_enc (g->db, "agraph.color_true", cons->context->pal.graph_true, 0);
	sdb_set_enc (g->db, "agraph.color_false", cons->context->pal.graph_false, 0);
}

R_API Sdb *r_agraph_get_sdb(RAGraph *g) {
	g->need_update_dim = true;
	g->need_set_layout = true;
	(void)check_changes (g, false, NULL, NULL);
	return g->db;
}

R_API void r_agraph_print(RAGraph *g) {
	agraph_print (g, false, NULL, NULL);
	if (g->graph->n_nodes > 0) {
		r_cons_newline ();
	}
}

R_API void r_agraph_print_json(RAGraph *g, PJ *pj) {
	RList *nodes = g->graph->nodes, *neighbours = NULL;
	RListIter *it, *itt;
	RGraphNode *node = NULL, *neighbour = NULL;
	if (!pj) {
		return;
	}
	r_list_foreach (nodes, it, node) {
		RANode *anode = (RANode *) node->data;
		char *label = strdup (anode->body);
		pj_o (pj);
		pj_ki (pj, "id", anode->gnode->idx);
		pj_ks (pj, "title", anode->title);
		pj_ks (pj, "body", label);
		pj_k (pj, "out_nodes");
		pj_a (pj);
		neighbours = anode->gnode->out_nodes;
		r_list_foreach (neighbours, itt, neighbour) {
			pj_i (pj, neighbour->idx);
		}
		pj_end (pj);
		pj_end (pj);
		free (label);
	}
}

R_API void r_agraph_set_title(RAGraph *g, const char *title) {
	free (g->title);
	g->title = title? strdup (title): NULL;
	sdb_set (g->db, "agraph.title", g->title, 0);
}

R_API RANode *r_agraph_add_node(const RAGraph *g, const char *title, const char *body, const char *color) {
	RANode *res = r_agraph_get_node (g, title);
	if (res) {
		return res;
	}
	res = R_NEW0 (RANode);
	if (!res) {
		return NULL;
	}

	res->title = title? r_str_trunc_ellipsis (title, 255) : strdup ("");
	res->body = (body && strlen (body))? r_str_endswith (body, "\n")?
		strdup (body): r_str_newf ("%s\n", body): strdup ("");	//XXX
	res->layer = -1;
	res->pos_in_layer = -1;
	res->is_dummy = false;
	res->is_reversed = false;
	res->klass = -1;
	res->color = color? strdup (color): NULL;
	res->difftype = -1;
	res->gnode = r_graph_add_node (g->graph, res);
	sdb_num_set (g->nodes, res->title, (ut64) (size_t) res, 0);
	if (res->title) {
		char *s, *estr, *b;
		size_t len;
		sdb_array_add (g->db, "agraph.nodes", res->title, 0);
		b = strdup (res->body);
		len = strlen (b);
		if (len > 0 && b[len - 1] == '\n') {
			b[len - 1] = '\0';
		}
		estr = sdb_encode ((const void *) b, -1);
		s = r_str_newf ("base64:%s", estr);
		free (estr);
		free (b);
		char *k = r_str_newf ("agraph.nodes.%s.body", res->title);
		sdb_set (g->db, k, s, 0);
		free (s);
		free (k);
	}
	return res;
}

R_API bool r_agraph_del_node(const RAGraph *g, const char *title) {
	r_strf_buffer (128);
	char *title_trunc = r_str_trunc_ellipsis (title, 255);
	RANode *an, *res = r_agraph_get_node (g, title_trunc);
	free (title_trunc);
	RGraphNode *gn;
	RListIter *it;

	if (!res) {
		return false;
	}
	sdb_set (g->nodes, res->title, NULL, 0);
	sdb_array_remove (g->db, "agraph.nodes", res->title, 0);
	sdb_set (g->db, r_strf ("agraph.nodes.%s", res->title), NULL, 0);
	sdb_set (g->db, r_strf ("agraph.nodes.%s.body", res->title), 0, 0);
	sdb_set (g->db, r_strf ("agraph.nodes.%s.x", res->title), NULL, 0);
	sdb_set (g->db, r_strf ("agraph.nodes.%s.y", res->title), NULL, 0);
	sdb_set (g->db, r_strf ("agraph.nodes.%s.w", res->title), NULL, 0);
	sdb_set (g->db, r_strf ("agraph.nodes.%s.h", res->title), NULL, 0);
	sdb_set (g->db, r_strf ("agraph.nodes.%s.neighbours", res->title), NULL, 0);

	const RList *innodes = r_graph_innodes (g->graph, res->gnode);
	graph_foreach_anode (innodes, it, gn, an) {
		const char *key = r_strf ("agraph.nodes.%s.neighbours", an->title);
		sdb_array_remove (g->db, key, res->title, 0);
	}

	r_graph_del_node (g->graph, res->gnode);
	res->gnode = NULL;

	ranode_free (res);
	return true;
}

static int user_node_cb(struct g_cb *user, const char *k UNUSED, const char *v) {
	RANodeCallback cb = user->node_cb;
	void *user_data = user->data;
	RANode *n = (RANode *) (size_t) sdb_atoi (v);
	if (n) {
		cb (n, user_data);
	}
	return 1;
}

static int user_edge_cb(struct g_cb *user, const char *k UNUSED, const char *v) {
	RAEdgeCallback cb = user->edge_cb;
	RAGraph *g = user->graph;
	void *user_data = user->data;
	RANode *an, *n = (RANode *) (size_t) sdb_atoi (v);
	if (!n) {
		return 0;
	}
	const RList *neigh = r_graph_get_neighbours (g->graph, n->gnode);
	RListIter *it;
	RGraphNode *gn;

	graph_foreach_anode (neigh, it, gn, an) {
		cb (n, an, user_data);
	}
	return 1;
}

R_API void r_agraph_foreach(RAGraph *g, RANodeCallback cb, void *user) {
	struct g_cb u = {
		.node_cb = cb,
		.data = user
	};
	sdb_foreach (g->nodes, (SdbForeachCallback) user_node_cb, &u);
}

R_API void r_agraph_foreach_edge(RAGraph *g, RAEdgeCallback cb, void *user) {
	struct g_cb u = {
		.graph = g,
		.edge_cb = cb,
		.data = user
	};
	sdb_foreach (g->nodes, (SdbForeachCallback) user_edge_cb, &u);
}

R_API RANode *r_agraph_get_first_node(const RAGraph *g) {
	const RList *l = r_graph_get_nodes (g->graph);
	RGraphNode *rgn = r_list_first (l);
	return get_anode (rgn);
}

R_API RANode *r_agraph_get_node(const RAGraph *g, const char *title) {
	char *title_trunc = title ? r_str_trunc_ellipsis (title, 255) : NULL;
	RANode *node = (RANode *) (size_t) sdb_num_get (g->nodes, title_trunc, NULL);
	free (title_trunc);
	return node;
}

R_API void r_agraph_add_edge(const RAGraph *g, RANode *a, RANode *b, bool highlight) {
	r_return_if_fail (g && a && b);
	r_graph_add_edge (g->graph, a->gnode, b->gnode);
	if (highlight) {
		ut64 aa = r_num_get (NULL, a->title);
		ut64 bb = r_num_get (NULL, b->title);
		r_strf_var (k, 64, "agraph.edge.0x%"PFMT64x"_0x%"PFMT64x".highlight", aa, bb);
		sdb_set (g->db, k, "true", 0);
	}
	if (a->title && b->title) {
		char *k = r_str_newf ("agraph.nodes.%s.neighbours", a->title);
		sdb_array_add (g->db, k, b->title, 0);
		free (k);
	}
}

R_API void r_agraph_add_edge_at(const RAGraph *g, RANode *a, RANode *b, int nth) {
	r_return_if_fail (g && a && b);
	if (a->title && b->title) {
		char *k = r_str_newf ("agraph.nodes.%s.neighbours", a->title);
		sdb_array_insert (g->db, k, nth, b->title, 0);
		free (k);
	}
	r_graph_add_edge_at (g->graph, a->gnode, b->gnode, nth);
}

R_API void r_agraph_del_edge(const RAGraph *g, RANode *a, RANode *b) {
	r_return_if_fail (g && a && b);
	if (a->title && b->title) {
		char *k = r_str_newf ("agraph.nodes.%s.neighbours", a->title);
		sdb_array_remove (g->db, k, b->title, 0);
		free (k);
	}
	r_graph_del_edge (g->graph, a->gnode, b->gnode);
}

R_API void r_agraph_reset(RAGraph *g) {
	r_return_if_fail (g);
	agraph_free_nodes (g);
	r_graph_reset (g->graph);
	r_agraph_set_title (g, NULL);
	sdb_reset (g->db);
	if (g->edges) {
		r_list_purge (g->edges);
	}
	g->nodes = sdb_new0 ();
	g->update_seek_on = NULL;
	g->need_reload_nodes = false;
	g->need_set_layout = true;
	g->need_update_dim = true;
	g->x = g->y = g->w = g->h = 0;
	agraph_sdb_init (g);
	g->curnode = NULL;
}

R_API void r_agraph_free(RAGraph *g) {
	if (g) {
		agraph_free_nodes (g);
		r_graph_free (g->graph);
		r_list_free (g->edges);
		r_agraph_set_title (g, NULL);
		sdb_free (g->db);
		r_cons_canvas_free (g->can);
		free (g);
	}
}

R_API RAGraph *r_agraph_new(RConsCanvas *can) {
	RAGraph *g = R_NEW0 (RAGraph);
	if (!g) {
		return NULL;
	}
	g->can = can;
	g->dummy = true;
	agraph_init (g);
	agraph_sdb_init (g);
	return g;
}

static void visual_offset(RAGraph *g, RCore *core) {
	char buf[256];
	int rows;
	r_cons_get_size (&rows);
	r_cons_gotoxy (0, rows);
	r_cons_flush ();
	core->cons->line->prompt_type = R_LINE_PROMPT_OFFSET;
	r_line_set_hist_callback (core->cons->line, &r_line_hist_offset_up, &r_line_hist_offset_down);
	r_line_set_prompt ("[offset]> ");
	strcpy (buf, "s ");
	if (r_cons_fgets (buf + 2, sizeof (buf) - 2, 0, NULL) > 0) {
		if (buf[2] == '.') {
			buf[1] = '.';
		}
		r_core_cmd0 (core, buf);
		r_line_set_hist_callback (core->cons->line, &r_line_hist_cmd_up, &r_line_hist_cmd_down);
	}
	core->cons->line->prompt_type = R_LINE_PROMPT_DEFAULT;
}

R_API void r_core_visual_find(RCore *core, RAGraph *g) {
	int offset = 0;
	int offset_max = 0;
	int rows;
	char buf[256];

	const bool asm_offset = r_config_get_b (core->config, "asm.offset");
	const bool asm_lines = r_config_get_b (core->config, "asm.lines");

	core->cons->line->prompt_type = R_LINE_PROMPT_OFFSET;
	r_line_set_prompt ("[find]> ");

	while (1) {
		r_cons_get_size (&rows);
		r_cons_gotoxy (0, rows - 1);
		r_cons_flush ();
		printf (Color_RESET);
		r_cons_flush ();

		r_cons_fgets (buf, sizeof (buf), 0, NULL);

		if (buf[0] == '\0') {
			break;
		}

find_next:
		if (core->cons->line->contents != NULL && strcmp (buf, core->cons->line->contents) == 0) {
			offset += 1;
			if (offset >= offset_max) {
				offset = 0;
			}
		} else {
			offset = 0;
		}

		r_config_set_b (core->config, "asm.offset", 1);
		r_config_set_b (core->config, "asm.lines", 0);

		if (offset == 0) {
			free (core->cons->line->contents);
			core->cons->line->contents = strdup (buf);

			char *lines_nbr = r_core_cmd_strf (core, "pdr~%s~^0x~?", buf);
			offset_max = atoi (lines_nbr);
			free (lines_nbr);
		}

		// TODO: filter `buf` to avoid command injection here
		char *line = r_core_cmd_strf (core, "pdr~%s~^0x:%d", buf, offset);
		r_str_trim (line);
		ut64 addr = r_num_get (core->num, line);
		if (addr > 0) {
			r_core_seek (core, addr, true);
			r_config_set (core->config, "scr.highlight", buf);
		} else {
			r_config_set (core->config, "scr.highlight", "");
		}

		r_config_set_b (core->config, "asm.offset", asm_offset);
		r_config_set_b (core->config, "asm.lines", asm_lines);
		if (g) {
			agraph_refresh (r_cons_singleton ()->event_data);
		} else {
			visual_refresh (core);
		}

		r_cons_clear_line (0);
		r_cons_printf (Color_RESET);
		if (addr > 0) {
			r_cons_gotoxy (0, 0);
			r_cons_printf ("[find]> match '%s'", line);
			R_LOG_INFO ("Found (%d/%d). Press 'n' for next, 'N' for prev, 'q' for quit, any other key to continue", offset+1, offset_max);
		} else {
			R_LOG_ERROR ("Text '%s' not found. Press 'q' for quit, any other key to conitnue", buf);
		}
		r_cons_flush ();

		free (line);

		char c = r_cons_readchar ();
		if (addr > 0) {
			if (c == ';') {
				char buf[256];
				r_line_set_prompt ("[comment]> ");
				if (r_cons_fgets (buf, sizeof (buf), 0, NULL) > 0) {
					r_core_cmdf (core, "'CC %s", buf);
				}
				r_line_set_prompt ("[find]> ");
				if (g) {
					g->need_reload_nodes = true;
				}
			}
			if (c == ':') {
				core->cons->event_resize = (RConsEvent)agraph_set_need_reload_nodes;
				r_core_visual_prompt_input (core);
				r_cons_set_raw (true);
				core->cons->event_resize = (RConsEvent)agraph_refresh_oneshot;
			}
			if (c == 'n' || c == 'j') {
				goto find_next;
			}
			if (c == 'N' || c == 'k') {
				offset -= 2;
				if (offset < -1) {
					offset = offset_max - 2;
				}
				goto find_next;
			}
		}
		if (c == 'q') {
			break;
		}
		if (g) {
			agraph_refresh (r_cons_singleton ()->event_data);
		} else {
			visual_refresh (core);
		}
	}

	free (core->cons->line->contents);
	core->cons->line->contents = NULL;
	r_config_set (core->config, "scr.highlight", "");
	core->cons->line->prompt_type = R_LINE_PROMPT_DEFAULT;
	r_config_set_b (core->config, "asm.offset", asm_offset);
	r_config_set_b (core->config, "asm.lines", asm_lines);
}

static void goto_asmqjmps(RAGraph *g, RCore *core) {
	const char *h = "[Fast goto call/jmp]> ";
	char obuf[R_CORE_ASMQJMPS_LEN_LETTERS + 1];
	int rows, i = 0;
	bool cont;

	r_cons_get_size (&rows);
	r_cons_gotoxy (0, rows);
	r_cons_clear_line (0);
	r_cons_print (Color_RESET);
	r_cons_print (h);
	r_cons_flush ();

	do {
		r_cons_set_raw (true);
		char ch = r_cons_readchar ();
		obuf[i++] = ch;
		r_cons_printf ("%c", ch);
		cont = isalpha ((ut8) ch) && !islower ((ut8) ch);
	} while (i < R_CORE_ASMQJMPS_LEN_LETTERS && cont);
	r_cons_flush ();

	obuf[i] = '\0';
	ut64 addr = r_core_get_asmqjmps (core, obuf);
	if (addr != UT64_MAX) {
		char *title = get_title (addr);
		RANode *addr_node = r_agraph_get_node (g, title);
		if (addr_node) {
			r_agraph_set_curnode (g, addr_node);
			r_core_seek (core, addr, false);
			agraph_update_seek (g, addr_node, true);
		} else {
			r_io_sundo_push (core->io, core->offset, 0);
			r_core_seek (core, addr, false);
		}
		free (title);
	}
}

static void seek_to_node(RANode *n, RCore *core) {
	ut64 off = r_anal_get_bbaddr (core->anal, core->offset);
	char *title = get_title (off);
	if (title && strcmp (title, n->title)) {
		r_core_cmdf (core, "s %s", n->title);
	}
	free (title);
}

static void graph_single_step_in(RCore *core, RAGraph *g) {
	if (r_config_get_b (core->config, "cfg.debug")) {
		if (core->print->cur_enabled) {
			// dcu 0xaddr
			r_core_cmdf (core, "dcu 0x%08"PFMT64x, core->offset + core->print->cur);
			core->print->cur_enabled = 0;
		} else {
			r_core_cmd (core, "ds", 0);
			r_core_cmd (core, ".dr*", 0);
		}
	} else {
		r_core_cmd (core, "aes", 0);
		r_core_cmd (core, ".ar*", 0);
	}
	g->is_instep = true;
	g->need_reload_nodes = true;
}

static void graph_single_step_over(RCore *core, RAGraph *g) {
	if (r_config_get_b (core->config, "cfg.debug")) {
		if (core->print->cur_enabled) {
			r_core_cmd (core, "dcr", 0);
			core->print->cur_enabled = 0;
		} else {
			r_core_cmd (core, "dso", 0);
			r_core_cmd (core, ".dr*", 0);
		}
	} else {
		r_core_cmd (core, "aeso", 0);
		r_core_cmd (core, ".ar*", 0);
	}
	g->is_instep = true;
	g->need_reload_nodes = true;
}

static void graph_breakpoint(RCore *core) {
	r_core_cmd (core, "dbs $$", 0);
}

static void graph_continue(RCore *core) {
	r_core_cmd (core, "dc", 0);
}

static void applyDisMode(RCore *core) {
	switch (core->visual.disMode) {
	case 0:
		r_config_set_b (core->config, "asm.pseudo", false);
		r_config_set_b (core->config, "asm.esil", false);
		break;
	case 1:
		r_config_set_b (core->config, "asm.pseudo", true);
		r_config_set_b (core->config, "asm.esil", false);
		break;
	case 2:
		r_config_set_b (core->config, "asm.pseudo", false);
		r_config_set_b (core->config, "asm.esil", true);
		break;
	}
}

static void rotateColor(RCore *core) {
	int color = r_config_get_i (core->config, "scr.color");
	if (++color > 3) {
		color = 0;
	}
	r_config_set_i (core->config, "scr.color", color);
}

// dupe in visual.c
static bool toggle_bb(RCore *core, ut64 addr) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
	if (fcn) {
		RAnalBlock *bb = r_anal_function_bbget_in (core->anal, fcn, addr);
		if (bb) {
			bb->folded = !bb->folded;
		} else {
			r_warn_if_reached ();
		}
		return true;
	}
	return false;
}

static char *get_graph_string(RCore *core, RAGraph *g) {
	int c = r_config_get_i (core->config, "scr.color");
	bool u = r_config_get_b (core->config, "scr.utf8");
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_b (core->config, "scr.utf8", false);
	r_core_visual_graph (core, g, NULL, false);
	char *s = strdup (r_cons_get_buffer ());
	r_cons_reset ();
	r_config_set_i (core->config, "scr.color", c);
	r_config_set_b (core->config, "scr.utf8", u);
	return s;
}

static void nextword(RCore *core, RAGraph *g, const char *word) {
	r_return_if_fail (core && core->graph && g && g->can && word);
	if (R_STR_ISEMPTY (word)) {
		return;
	}
	RAGraphHits *gh = &g->ghits;
	RConsCanvas *can = g->can;
	if (gh->word_list.len && gh->old_word && !strcmp (word, gh->old_word)) {
		if (gh->word_nth >= gh->word_list.len) {
			gh->word_nth = 0;
		}

		struct r_agraph_location *pos = r_vector_at (&gh->word_list, gh->word_nth);
		gh->word_nth++;
		if (pos) {
			can->sx = -pos->x + can->w / 2;
			can->sy = -pos->y + can->h / 2;
		}
		return;
	} else {
		r_vector_clear (&gh->word_list);
	}
	char *s = get_graph_string (core, g);
	r_cons_clear00 ();
	r_cons_flush ();
	const size_t MAX_COUNT = 4096;
	const char *a = NULL;
	size_t count = 0;
	int x = 0, y = 0;
	for (count = 0; count < MAX_COUNT; count++) {
		a = r_str_str_xy (s, word, a, &x, &y);
		if (!a) {
			break;
		}
		struct r_agraph_location *pos = r_vector_push (&gh->word_list, NULL);
		if (pos) {
			pos->x = x + g->x;
			pos->y = y + g->y;
		}
	}
	free (gh->old_word);
	gh->old_word = strdup (word);
	free (s);
	if (a || count > 0) {
		nextword (core, g, word);
	}
}

R_API bool r_core_visual_graph(RCore *core, RAGraph *g, RAnalFunction *_fcn, int mode) {
	bool is_interactive = (mode != 0);
	if (is_interactive && !r_cons_is_interactive ()) {
		R_LOG_ERROR ("Interactive graph mode requires 'e scr.interactive=true'");
		return false;
	}
	r_cons_set_raw (true);
	int o_asmqjmps_letter = core->is_asmqjmps_letter;
	int o_vmode = core->vmode;
	int exit_graph = false, is_error = false;
	bool must_update_seek = false;
	struct agraph_refresh_data *grd;
	int okey, key;
	RAnalFunction *fcn = NULL;
	const char *key_s;
	RConsCanvas *can, *o_can = NULL;
	bool graph_allocated = false;
	int movspeed;
	int ret, invscroll;
	RConfigHold *hc = r_config_hold_new (core->config);
	if (!hc) {
		return false;
	}
	r_config_hold (hc, "asm.pseudo", "asm.esil", "asm.cmt.right", NULL);

	int h, w = r_cons_get_size (&h);
	can = r_cons_canvas_new (w, h);
	if (!can) {
		w = 80;
		h = 25;
		can = r_cons_canvas_new (w, h);
		if (!can) {
			R_LOG_ERROR ("Cannot create RCons.canvas context. Invalid screen "
					"size? See scr.cols + scr.rows");
			r_config_hold_free (hc);
			return false;
		}
	}
	can->linemode = r_config_get_b (core->config, "graph.linemode");
	can->color = r_config_get_i (core->config, "scr.color");

	if (!g) {
		graph_allocated = true;
		fcn = _fcn? _fcn: r_anal_get_fcn_in (core->anal, core->offset, 0);
		if (!fcn) {
			R_LOG_ERROR ("No function to graph");
			r_config_hold_restore (hc);
			r_config_hold_free (hc);
			r_cons_canvas_free (can);
			return false;
		}
		check_function_modified (core, fcn);
		g = r_agraph_new (can);
		if (!g) {
			r_cons_canvas_free (can);
			r_config_hold_restore (hc);
			r_config_hold_free (hc);
			return false;
		}
		g->is_tiny = mode == 2;
		g->layout = r_config_get_i (core->config, "graph.layout");
		g->dummy = r_config_get_i (core->config, "graph.dummy");
		g->show_node_titles = r_config_get_i (core->config, "graph.ntitles");
	} else {
		o_can = g->can;
	}

	g->can = can;
	g->movspeed = r_config_get_i (core->config, "graph.scroll");
	const int graph_zoom = r_config_get_i (core->config, "graph.zoom");
	if (graph_zoom) {
		agraph_set_zoom (g, graph_zoom);
	}
	g->show_node_titles = r_config_get_i (core->config, "graph.ntitles");
	g->show_node_body = r_config_get_b (core->config, "graph.body");
	g->show_node_bubble = r_config_get_i (core->config, "graph.bubble");
	g->on_curnode_change = (RANodeCallback) seek_to_node;
	g->on_curnode_change_data = core;
	g->edgemode = r_config_get_i (core->config, "graph.edges");
	g->hints = r_config_get_b (core->config, "graph.hints");
	g->is_interactive = is_interactive;
	bool asm_comments = r_config_get_b (core->config, "asm.comments");
	r_config_set_b (core->config, "asm.comments", r_config_get_b (core->config, "graph.comments"));

	/* we want letters as shortcuts for call/jmps */
	core->is_asmqjmps_letter = true;
	core->vmode = true;

	grd = R_NEW0 (struct agraph_refresh_data);
	if (!grd) {
		r_cons_canvas_free (can);
		r_config_hold_restore (hc);
		r_config_hold_free (hc);
		r_agraph_free (g);
		return false;
	}
	grd->g = g;
	grd->fs = is_interactive == 1;
	grd->core = core;
	grd->follow_offset = _fcn == NULL;
	grd->fcn = fcn? &fcn: NULL;
	ret = agraph_refresh (grd);
	if (!ret || is_interactive != 1) {
		r_cons_newline ();
		exit_graph = true;
		is_error = !ret;
	}
	fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
	if (fcn) {
		get_bbupdate (g, core, fcn);
		fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
	}

	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = grd;
	core->cons->event_resize = (RConsEvent) agraph_refresh_oneshot;

	r_cons_break_push (NULL, NULL);
	if (mode == 3) { // XXX wrong usage or buggy RGraph.domTree()
		// dominance tree here
		const RList *l = r_graph_get_nodes (g->graph);
		RGraphNode *root = r_list_first (l);
		if (root) {
			RGraph *dg = r_graph_dom_tree (g->graph, root);
			if (dg) {
				// XXX double free - r_graph_free (g->graph);
				g->graph = dg;
			} else {
				R_LOG_WARN ("Cannot compute the dominance tree");
				sleep (1);
			}
		}
	}

	while (!exit_graph && !is_error && !r_cons_is_breaked ()) {
		w = r_cons_get_size (&h);
		invscroll = r_config_get_b (core->config, "graph.invscroll");
		ret = agraph_refresh (grd);

		if (!ret) {
			is_error = true;
			break;
		}
		showcursor (core, false);

		// r_core_graph_inputhandle()
		r_cons_set_raw (true);
		okey = r_cons_readchar ();
		key = r_cons_arrow_to_hjkl (okey);

		if (core->cons->mouse_event) {
			movspeed = r_config_get_i (core->config, "scr.wheel.speed");
			switch (key) {
			case 'j':
			case 'k':
				switch (core->visual.mousemode) {
				case 0: break;
				case 1: key = key == 'k'? 'h': 'l'; break;
				case 2: key = key == 'k'? 'J': 'K'; break;
				case 3: key = key == 'k'? 'L': 'H'; break;
				}
				break;
			}
		} else {
			movspeed = g->movspeed;
		}
		const char *cmd;
		switch (key) {
		case '-':
			agraph_set_zoom (g, g->zoom - ZOOM_STEP);
			g->force_update_seek = true;
			break;
		case '+':
			agraph_set_zoom (g, g->zoom + ZOOM_STEP);
			g->force_update_seek = true;
			break;
		case '0':
			agraph_set_zoom (g, ZOOM_DEFAULT);
			agraph_update_seek (g, get_anode (g->curnode), true);
			// update scroll (with minor shift)
			break;
			// Those hardcoded keys are useful only for aegi, should add subcommand of ag to set key actions
		case '1':
			r_core_cmd0 (core, "so;.aeg*");
			break;
		case '2':
			r_core_cmd0 (core, "so -1;.aeg*");
			break;
		case '=':
		{         // TODO: edit
			showcursor (core, true);
			const char *cmd = r_config_get (core->config, "cmd.gprompt");
			r_line_set_prompt ("cmd.gprompt> ");
			core->cons->line->contents = strdup (cmd);
			const char *buf = r_line_readline ();
			core->cons->line->contents = NULL;
			r_config_set (core->config, "cmd.gprompt", buf);
			showcursor (core, false);
		}
		break;
		case '|':
			{
				int e = r_config_get_i (core->config, "graph.layout");
				if (++e > 1) {
					e = 0;
				}
				r_config_set_i (core->config, "graph.layout", e);
				g->layout = r_config_get_i (core->config, "graph.layout");
				g->need_update_dim = true;
				g->need_set_layout = true;
			}
			g->discroll = 0;
			agraph_update_seek (g, get_anode (g->curnode), true);
			break;
		case 'e':
			{
				int e = r_config_get_i (core->config, "graph.edges");
				e++;
				if (e > 2) {
					e = 0;
				}
				r_config_set_i (core->config, "graph.edges", e);
				g->edgemode = e;
				g->need_update_dim = true;
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
				if (fcn) {
					get_bbupdate (g, core, fcn);
				}
			}
			break;
		case '\\':
			nextword (core, g, r_config_get (core->config, "scr.highlight"));
			break;
		case 'b':
			r_core_visual_browse (core, "");
			break;
		case 'E':
			{
				int e = r_config_get_i (core->config, "graph.linemode");
				e--;
				if (e < 0) {
					e = 1;
				}
				r_config_set_i (core->config, "graph.linemode", e);
				g->can->linemode = e;
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
				if (fcn) {
					get_bbupdate (g, core, fcn);
				}
			}
			break;
		case 13:
			agraph_update_seek (g, get_anode (g->curnode), true);
			must_update_seek = true;
			exit_graph = true;
			break;
		case '>':
			if (fcn && r_cons_yesno ('y', "Compute function callgraph? (Y/n)")) {
				r_core_cmd0 (core, "ag-;.agc* @$FB;.axfg @$FB;aggi");
			}
			break;
		case '<':
			// r_core_visual_refs (core, true, false);
			if (fcn) {
				r_core_cmd0 (core, "ag-;.axtg $FB;aggi");
			}
			break;
		case 'G':
			r_core_cmd0 (core, "ag-;.dtg*;aggi");
			break;
		case 'V':
			if (fcn) {
				agraph_toggle_callgraph (g);
			}
			break;
		case 'Z':
			if (okey == 27) { // shift-tab
				agraph_prev_node (g);
			} else {
				RANode *n = get_anode (g->curnode);
				if (n) {
					ut64 addr = r_num_get (NULL, n->title);
					toggle_bb (core, addr);
					g->need_reload_nodes = true;
				}
			}
			break;
		case 's':
			if (!fcn) {
				break;
			}
			key_s = r_config_get (core->config, "key.s");
			if (key_s && *key_s) {
				r_core_cmd0 (core, key_s);
			} else {
				graph_single_step_in (core, g);
			}
			g->discroll = 0;
			agraph_update_seek (g, get_anode (g->curnode), true);
			break;
		case 'S':
			if (fcn) {
				graph_single_step_over (core, g);
			}
			break;
		case 'x':
		case 'X':
		{
			if (!fcn) {
				break;
			}
			ut64 old_off = core->offset;
			ut64 off = r_anal_get_bbaddr (core->anal, core->offset);
			r_core_seek (core, off, false);
			if ((key == 'x' && !r_core_visual_refs (core, true, true)) ||
			    (key == 'X' && !r_core_visual_refs (core, false, true))) {
				r_core_seek (core, old_off, false);
			}
			break;
		}
		case '@': // tab
			r_config_set_i (core->config, "graph.layout",
				r_config_get_i (core->config, "graph.layout")? 0: 1);
			g->discroll = 0;
			g->layout = r_config_get_i (core->config, "graph.layout");
			g->need_reload_nodes = true;
			agraph_update_seek (g, get_anode (g->curnode), true);
			break;
		case '%':
			showcursor (core, true);
			r_core_visual_find (core, g);
			showcursor (core, false);
			break;
		case 9: // tab
			agraph_next_node (g);
			g->discroll = 0;
			break;
		case '?':
			r_cons_clear00 ();
			RStrBuf *rsb = r_strbuf_new ("");
			r_core_visual_append_help (rsb, "Visual Graph Mode (VV) Help", help_msg_visual_graph);
			ret = r_cons_less_str (r_strbuf_get (rsb), "?");
			r_strbuf_free (rsb);
			break;
		case '"':
			r_config_toggle (core->config, "graph.refs");
			break;
		case '#':
			if (g->mode == R_AGRAPH_MODE_COMMENTS) {
				g->mode = R_AGRAPH_MODE_NORMAL;
			} else {
				g->mode = R_AGRAPH_MODE_COMMENTS;
			}
			g->need_reload_nodes = true;
			g->discroll = 0;
			agraph_update_seek (g, get_anode (g->curnode), true);
			// r_config_toggle (core->config, "graph.hints");
			break;
		case 'p':
			g->mode = next_mode (g->mode);
			g->need_reload_nodes = true;
			agraph_update_seek (g, get_anode (g->curnode), true);
			break;
		case 'P':
			if (!fcn) {
				break;
			}
			g->mode = prev_mode (g->mode);
			g->need_reload_nodes = true;
			agraph_update_seek (g, get_anode (g->curnode), true);
			break;
		case 'o':
			goto_asmqjmps (g, core);
			break;
		case 'g':
			showcursor (core, true);
			visual_offset (g, core);
			showcursor (core, false);
			break;
		case 'O':
			if (!fcn) {
				break;
			}
			core->visual.disMode = (core->visual.disMode + 1) % 3;
			applyDisMode (core);
			g->need_reload_nodes = true;
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				get_bbupdate (g, core, fcn);
			}
			break;
		case 'u':
		{
			RIOUndos *undo = r_io_sundo (core->io, core->offset);
			if (undo) {
				r_core_seek (core, undo->off, false);
			} else {
				R_LOG_ERROR ("Cannot undo");
			}
			if (r_config_get_i (core->config, "graph.few")) {
				g->need_reload_nodes = true;
			}
			break;
		}
		case 'U':
		{
			RIOUndos *undo = r_io_sundo_redo (core->io);
			if (undo) {
				r_core_seek (core, undo->off, false);
			} else {
				R_LOG_ERROR ("Cannot redo");
			}
			if (r_config_get_i (core->config, "graph.few")) {
				g->need_reload_nodes = true;
			}
			break;
		}
		case 'r':
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				g->layout = r_config_get_i (core->config, "graph.layout");
				g->need_reload_nodes = true;
			}
			// TODO: toggle shortcut hotkeys
			if (r_config_get_b (core->config, "asm.hint.call")) {
				r_core_cmd_call (core, "e!asm.hint.call");
				r_core_cmd_call (core, "e!asm.hint.jmp");
			} else if (r_config_get_b (core->config, "asm.hint.jmp")) {
				r_core_cmd_call (core, "e!asm.hint.jmp");
				r_core_cmd_call (core, "e!asm.hint.lea");
			} else if (r_config_get_b (core->config, "asm.hint.lea")) {
				r_core_cmd_call (core, "e!asm.hint.lea");
				r_core_cmd_call (core, "e!asm.hint.call");
			}
			break;
		case 'R':
			if (r_config_get_b (core->config, "scr.randpal")) {
				r_core_cmd_call (core, "ecr");
			} else {
				r_core_cmd_call (core, "ecn");
			}
			g->edgemode = r_config_get_i (core->config, "graph.edges");
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				get_bbupdate (g, core, fcn);
			}
			break;
		case '$':
			r_core_cmd (core, "dr PC=$$", 0);
			r_core_cmd (core, "sr PC", 0);
			g->need_reload_nodes = true;
			break;
		case '!':
			r_core_panels_root (core, core->panels_root);
			break;
		case 'y':
#if 0
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				r_config_toggle (core->config, "graph.comments");
				g->need_reload_nodes = true;
			}
#else
			r_config_toggle (core->config, "graph.comments");
			g->need_reload_nodes = true;
#endif
			break;
		case '[':
			if (core->print->cur_enabled) {
				int scrcols = r_config_get_i (core->config, "hex.cols");
				if (scrcols > 1) {
					r_config_set_i (core->config, "hex.cols", scrcols - 1);
				}
			} else {
				int n = r_config_get_i (core->config, "graph.bb.maxwidth");
				n -= 5;
				if (n < 20) {
					n = 0;
				}
				r_config_set_i (core->config, "graph.bb.maxwidth", n);
				g->need_reload_nodes = true;
				g->bb_maxwidth = n;
			}
			break;
		case ']':
			if (core->print->cur_enabled) {
				int scrcols = r_config_get_i (core->config, "hex.cols");
				r_config_set_i (core->config, "hex.cols", scrcols + 1);
			} else {
				int n = r_config_get_i (core->config, "graph.bb.maxwidth");
				if (n < 1) {
					n = 20;
				} else {
					n += 5;
				}
				r_config_set_i (core->config, "graph.bb.maxwidth", n);
				g->need_reload_nodes = true;
				g->bb_maxwidth = n;
			}
			break;
		case ';':
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				showcursor (core, true);
				char buf[256];
				r_line_set_prompt ("[comment]> ");
				if (r_cons_fgets (buf, sizeof (buf), 0, NULL) > 0) {
					r_core_cmdf (core, "\"CC %s\"", buf);
				}
				g->need_reload_nodes = true;
				showcursor (core, false);
			}
			break;
		case 'C':
			rotateColor (core);
			break;
		case 'm':
			// mark current x/y + offset
			{
				r_cons_gotoxy (0, 0);
				r_cons_printf (R_CONS_CLEAR_LINE"Set shortcut key for 0x%"PFMT64x"\n", core->offset);
				r_cons_flush ();
				int ch = r_cons_readchar ();
				if (ch > 0) {
					r_core_vmark_set (core, ch, core->offset, can->sx, can->sy);
				}
			}
			break;
		case '\'':
			// go to given mark
			{
				r_cons_gotoxy (0, 2);
				if (r_core_vmark_dump (core, 'v')) {
					r_cons_flush ();
					const int ch = r_cons_readchar ();
					r_core_vmark_seek (core, ch, g);
					core->visual.coming_from_vmark = true;
				}
			}
			break;
		case 'M':
#if 0
			mousemode++;
			if (!mousemodes[mousemode]) {
				mousemode = 0;
			}
			break;
#else
			core->visual.mousemode--;
			if (core->visual.mousemode < 0) {
				core->visual.mousemode = 3;
			}
#endif
			break;
		case '(':
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				r_core_cmd0 (core, "wao recj@B:-1");
				g->need_reload_nodes = true;
			}
			break;
		case ')':
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				rotateAsmemu (core);
				g->need_reload_nodes = true;
			}
			break;
		case 'd':
			{
				showcursor (core, true);
				r_core_visual_define (core, "", 0);
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
				if (fcn) {
					get_bbupdate (g, core, fcn);
				}
				showcursor (core, false);
			}
			break;
		case 'D':
			g->is_dis = !g->is_dis;
			break;
		case 'n':
			r_core_seek_next (core, r_config_get (core->config, "scr.nkey"));
			break;
		case 'N':
			r_core_seek_previous (core, r_config_get (core->config, "scr.nkey"));
			break;
		case 'Y':
			agraph_toggle_tiny (g);
			agraph_update_seek (g, get_anode (g->curnode), true);
			break;
		case 'z':
			agraph_toggle_mini (g);
			g->discroll = 0;
			agraph_update_seek (g, get_anode (g->curnode), true);
			break;
		case 'v':
			r_core_visual_anal (core, NULL);
			break;
		case 'J':
			// copypaste from 'j'
			if (core->visual.graphCursor) {
				int speed = (okey == 27)? PAGEKEY_SPEED: movspeed;
				graphNodeMove (g, 'j', speed * 2);
			} else {
				can->sy -= (5 * movspeed) * (invscroll? -1: 1);
			}
			break;
		case 'K':
			if (core->visual.graphCursor) {
				int speed = (okey == 27)? PAGEKEY_SPEED: movspeed;
				graphNodeMove (g, 'k', speed * 2);
			} else {
				can->sy += (5*movspeed) * (invscroll? -1: 1);
			}
			break;
		case 'H':
			if (core->visual.graphCursor) {
				// move node canvas faster
				graphNodeMove (g, 'h', movspeed * 2);
			} else {
				// scroll canvas faster
				if (okey == 27) {
					// handle home key
					const RGraphNode *gn = find_near_of (g, NULL, true);
					g->update_seek_on = get_anode (gn);
				} else {
					can->sx += (5 * movspeed) * (invscroll? -1: 1);
				}
			}
			break;
		case 'L':
			if (core->visual.graphCursor) {
				graphNodeMove (g, 'l', movspeed * 2);
			} else {
				can->sx -= (5 * movspeed) * (invscroll? -1: 1);
			}
			break;
		case 'c':
			core->visual.graphCursor = !core->visual.graphCursor;
			break;
		case 'j':
			if (g->is_dis) {
				r_core_cmd_call (core, "so 1");
			} else {
				if (core->visual.graphCursor) {
					int speed = (okey == 27)? PAGEKEY_SPEED: movspeed;
					graphNodeMove (g, 'j', speed);
				} else {
					// scroll canvas
					can->sy -= movspeed * (invscroll? -1: 1);
				}
			}
			break;
		case 'k':
			if (g->is_dis) {
				r_core_cmd_call (core, "so -1");
			} else {
				if (core->visual.graphCursor) {
					int speed = (okey == 27)? PAGEKEY_SPEED: movspeed;
					graphNodeMove (g, 'k', speed);
				} else {
					// scroll canvas
					can->sy += movspeed * (invscroll? -1: 1);
				}
			}
			break;
		case 'l':
			if (core->visual.graphCursor) {
				int speed = (okey == 27)? PAGEKEY_SPEED: movspeed;
				graphNodeMove (g, 'l', speed);
			} else {
				can->sx -= movspeed * (invscroll? -1: 1);
			}
			break;
		case 'h':
			if (core->visual.graphCursor) {
				int speed = (okey == 27)? PAGEKEY_SPEED: movspeed;
				graphNodeMove (g, 'h', speed);
			} else {
				can->sx += movspeed * (invscroll? -1: 1);
			}
			break;
		case '^':
			{
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
				if (fcn) {
					r_core_seek (core, fcn->addr, false);
				}
			}
			agraph_update_seek (g, get_anode (g->curnode), true);
			break;
		case ',':
			r_config_toggle (core->config, "graph.few");
			g->need_reload_nodes = true;
			agraph_update_seek (g, get_anode (g->curnode), true);
			break;
		case '.':
			g->discroll = 0;
			agraph_update_seek (g, get_anode (g->curnode), true);
			break;
		case 'i':
			agraph_follow_innodes (g, true);
			break;
		case 'I':
			agraph_follow_innodes (g, false);
			break;
		case 't':
			agraph_follow_true (g);
			break;
		case 'T':
			// XXX WIP	agraph_merge_child (g, 0);
			break;
		case 'f':
			agraph_follow_false (g);
			break;
		case 'F':
			if (okey == 27) {
				// handle end key
				const RGraphNode *gn = find_near_of (g, NULL, false);
				g->update_seek_on = get_anode (gn);
			} else {
				// agraph_merge_child (g, 1);
				r_core_visual_trackflags (core);
			}
			break;
		case '/':
			showcursor (core, true);
			r_core_cmd0 (core, "?i highlight;e scr.highlight=`yp`");
			showcursor (core, false);
			break;
		case ':':
			core->cons->event_resize = (RConsEvent)agraph_set_need_reload_nodes;
			r_core_visual_prompt_input (core);
			r_cons_set_raw (true);
			core->cons->event_resize = (RConsEvent)agraph_refresh_oneshot;
			if (!g) {
				g->need_reload_nodes = true; // maybe too slow and unnecessary sometimes? better be safe and reload
				get_bbupdate (g, core, fcn);
			}
			break;
		case '&':
			{
			RIOUndos *undo = r_io_sundo (core->io, core->offset);
			if (undo) {
				r_io_sundo_redo (core->io);
				char *c = r_str_newf ("agraph.edge.0x%"PFMT64x"_0x%"PFMT64x".highlight", undo->off, core->offset);
				sdb_set (g->db, c, "true", 0);
				free (c);
			}
			}
			break;
		case 'w':
			agraph_toggle_speed (g, core);
			break;
		case '_':
			r_core_visual_hudstuff (core);
			break;
		case R_CONS_KEY_F1:
			cmd = r_config_get (core->config, "key.f1");
			if (cmd && *cmd) {
				(void) r_core_cmd0 (core, cmd);
				g->need_reload_nodes = true;
			}
			break;
		case R_CONS_KEY_F2:
			cmd = r_config_get (core->config, "key.f2");
			if (R_STR_ISNOTEMPTY (cmd)) {
				r_core_cmd0 (core, cmd);
				g->need_reload_nodes = true;
			} else {
				graph_breakpoint (core);
			}
			break;
		case R_CONS_KEY_F3:
			cmd = r_config_get (core->config, "key.f3");
			if (R_STR_ISNOTEMPTY (cmd)) {
				r_core_cmd0 (core, cmd);
				g->need_reload_nodes = true;
			}
			break;
		case R_CONS_KEY_F4:
			cmd = r_config_get (core->config, "key.f4");
			if (R_STR_ISNOTEMPTY (cmd)) {
				r_core_cmd0 (core, cmd);
				g->need_reload_nodes = true;
			}
			break;
		case R_CONS_KEY_F5:
			cmd = r_config_get (core->config, "key.f5");
			if (R_STR_ISNOTEMPTY (cmd)) {
				r_core_cmd0 (core, cmd);
				g->need_reload_nodes = true;
			}
			break;
		case R_CONS_KEY_F6:
			cmd = r_config_get (core->config, "key.f6");
			if (cmd && *cmd) {
				(void)r_core_cmd0 (core, cmd);
				g->need_reload_nodes = true;
			}
			break;
		case R_CONS_KEY_F7:
			cmd = r_config_get (core->config, "key.f7");
			if (R_STR_ISNOTEMPTY (cmd)) {
				(void)r_core_cmd0 (core, cmd);
				g->need_reload_nodes = true;
			} else {
				graph_single_step_in (core, g);
			}
			break;
		case R_CONS_KEY_F8:
			cmd = r_config_get (core->config, "key.f8");
			if (R_STR_ISNOTEMPTY (cmd)) {
				(void)r_core_cmd0 (core, cmd);
				g->need_reload_nodes = true;
			} else {
				graph_single_step_over (core, g);
			}
			break;
		case R_CONS_KEY_F9:
			cmd = r_config_get (core->config, "key.f9");
			if (R_STR_ISNOTEMPTY (cmd)) {
				(void)r_core_cmd0 (core, cmd);
				g->need_reload_nodes = true;
			} else {
				graph_continue (core);
			}
			break;
		case R_CONS_KEY_F10:
			cmd = r_config_get (core->config, "key.f10");
			if (R_STR_ISNOTEMPTY (cmd)) {
				(void)r_core_cmd0 (core, cmd);
				g->need_reload_nodes = true;
			}
			break;
		case R_CONS_KEY_F11:
			cmd = r_config_get (core->config, "key.f11");
			if (R_STR_ISNOTEMPTY (cmd)) {
				(void)r_core_cmd0 (core, cmd);
				g->need_reload_nodes = true;
			}
			break;
		case R_CONS_KEY_F12:
			cmd = r_config_get (core->config, "key.f12");
			if (R_STR_ISNOTEMPTY (cmd)) {
				(void)r_core_cmd0 (core, cmd);
				g->need_reload_nodes = true;
			}
			break;
		case -1: // EOF
		case ' ':
		case 'Q':
		case 'q':
			if (g->is_callgraph) {
				agraph_toggle_callgraph (g);
			} else {
				exit_graph = true;
			}
			break;
		case 27: // ESC
			if (r_cons_readchar () == 91) {
				if (r_cons_readchar () == 90) {
					agraph_prev_node (g);
				}
			}
			break;
		default:
			break;
		}
	}
	r_vector_fini (&g->ghits.word_list);
	r_cons_break_pop ();
	r_config_set_b (core->config, "asm.comments", asm_comments);
	core->cons->event_resize = NULL;
	core->cons->event_data = NULL;
	core->vmode = o_vmode;
	core->is_asmqjmps_letter = o_asmqjmps_letter;
	core->keep_asmqjmps = false;

	free (grd);
	if (graph_allocated) {
		r_agraph_free (g);
	} else {
		g->can = o_can;
	}
	r_config_hold_restore (hc);
	r_config_hold_free (hc);
	if (must_update_seek) {
		return -1;
	}
	return !is_error;
}

R_API RAGraph *r_agraph_new_from_graph(const RGraph *graph, RAGraphTransitionCBs *cbs, void *user) {
	r_return_val_if_fail (graph && cbs && cbs->get_title && cbs->get_body, NULL);

	RAGraph *result_agraph = r_agraph_new (r_cons_canvas_new (1, 1));
	if (!result_agraph) {
		return NULL;
	}
	result_agraph->need_reload_nodes = false;
	// Cache lookup to build edges
	HtPPOptions pointer_options = {0};
	HtPP /*<RGraphNode *node, RANode *anode>*/ *hashmap = ht_pp_new_opt (&pointer_options);

	if (!hashmap) {
		r_agraph_free (result_agraph);
		return NULL;
	}
	// List of the new RANodes
	RListIter *iter;
	RGraphNode *node;
	// Traverse the list, create new ANode for each Node
	r_list_foreach (graph->nodes, iter, node) {
		char *title = cbs->get_title (node->data, user);
		char *body = cbs->get_body (node->data, user);
		RANode *a_node = r_agraph_add_node (result_agraph, title, body, NULL);
		R_FREE (title);
		R_FREE (body);
		if (!a_node) {
			goto failure;
		}
		ht_pp_insert (hashmap, node, a_node);
	}

	// Traverse the nodes again, now build up the edges
	r_list_foreach (graph->nodes, iter, node) {
		RANode *a_node = ht_pp_find (hashmap, node, NULL);
		if (!a_node) {
			goto failure; // shouldn't happen in correct graph state
		}

		RListIter *neighbour_iter;
		RGraphNode *neighbour;
		r_list_foreach (node->in_nodes, neighbour_iter, neighbour) {
			RANode *a_neighbour = ht_pp_find (hashmap, neighbour, NULL);
			if (!a_neighbour) {
				goto failure;
			}
			r_agraph_add_edge (result_agraph, a_neighbour, a_node, false);
		}
	}

	ht_pp_free (hashmap);
	return result_agraph;
failure:
	ht_pp_free (hashmap);
	r_agraph_free (result_agraph);
	return NULL;
}
