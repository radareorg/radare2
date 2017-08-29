/* Copyright radare2 - 2014-2017 - pancake, ret2libc */

#include <r_core.h>
#include <r_cons.h>
#include <ctype.h>
#include <limits.h>

static int mousemode = 0;
static const char *mousemodes[] = {
	"canvas-y",
	"canvas-x",
	"node-y",
	"node-x",
	NULL
};

#define GRAPH_MERGE_FEATURE 0

#define BORDER 3
#define BORDER_WIDTH 4
#define BORDER_HEIGHT 3
#define MARGIN_TEXT_X 2
#define MARGIN_TEXT_Y 2
#define HORIZONTAL_NODE_SPACING 6
#define VERTICAL_NODE_SPACING 4
#define MIN_NODE_WIDTH 22
#define MIN_NODE_HEIGHT BORDER_HEIGHT
#define TITLE_LEN 128
#define DEFAULT_SPEED 1
#define PAGEKEY_SPEED (h / 2)
/* 15 */
#define MINIGRAPH_NODE_TEXT_CUR "<@@@@@@>"
#define MINIGRAPH_NODE_MIN_WIDTH 8
#define MINIGRAPH_NODE_TITLE_LEN 4
#define MINIGRAPH_NODE_CENTER_X 3
#define MININODE_MIN_WIDTH 16

#define ZOOM_STEP 10
#define ZOOM_DEFAULT 100

#define BODY_OFFSETS    0x1
#define BODY_SUMMARY    0x2

#define hash_set(sdb, k, v) (sdb_num_set (sdb, sdb_fmt (0, "%"PFMT64u, (ut64) (size_t) k), (ut64) (size_t) v, 0))
#define hash_get(sdb, k) (sdb_num_get (sdb, sdb_fmt (0, "%"PFMT64u, (ut64) (size_t) k), NULL))
#define hash_get_rnode(sdb, k) ((RGraphNode *) (size_t) hash_get (sdb, k))
#define hash_get_rlist(sdb, k) ((RList *) (size_t) hash_get (sdb, k))
#define hash_get_int(sdb, k) ((int) hash_get (sdb, k))
/* dont use macros for this */
#define get_anode(gn) (gn? (RANode *) gn->data: NULL)

#define graph_foreach_anode(list, it, pos, anode)\
	if (list) for (it = list->head; it && (pos = it->data) && (pos) && (anode = (RANode *) pos->data); it = it->n)

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
	int is_reversed;
} AEdge;

struct layer_t {
	int n_nodes;
	RGraphNode **nodes;
	int position;
	int height;
	int width;
};

struct agraph_refresh_data {
	RCore *core;
	RAGraph *g;
	RAnalFunction **fcn;
	int fs;
};

#define G(x, y) r_cons_canvas_gotoxy (g->can, x, y)
#define W(x) r_cons_canvas_write (g->can, x)
#define B(x, y, w, h) r_cons_canvas_box (g->can, x, y, w, h, g->color_box)
#define B1(x, y, w, h) r_cons_canvas_box (g->can, x, y, w, h, g->color_box2)
#define B2(x, y, w, h) r_cons_canvas_box (g->can, x, y, w, h, g->color_box3)
#define F(x, y, x2, y2, c) r_cons_canvas_fill (g->can, x, y, x2, y2, c, 0)

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

static int next_mode(int mode) {
	return (mode + 1) % R_AGRAPH_MODE_MAX;
}

static int prev_mode(int mode) {
	return (mode + R_AGRAPH_MODE_MAX - 1) % R_AGRAPH_MODE_MAX;
}

static const char *mode2str(const RAGraph *g, const char *prefix) {
	static char m[20];
	const char *submode;

	if (is_tiny (g)) {
		submode = "TINY";
	} else if (is_mini (g)) {
		submode = "MINI";
	} else if (is_offset (g)) {
		submode = "OFF";
	} else if (is_summary (g)) {
		submode = "SUMM";
	} else {
		submode = "NORM";
	}

	snprintf (m, sizeof (m), "%s-%s", prefix, submode);
	return m;
}

static int mode2opts(const RAGraph *g) {
	int opts = 0;
	if (is_offset (g)) {
		opts |= BODY_OFFSETS;
	}
	if (is_summary (g)) {
		opts |= BODY_SUMMARY;
	}
	return opts;
}

static char *get_title(ut64 addr) {
	return r_str_newf ("0x%"PFMT64x, addr);
}

static int agraph_refresh(struct agraph_refresh_data *grd);

static void update_node_dimension(const RGraph *g, int is_mini, int zoom) {
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
			unsigned int len;
			n->w = r_str_bounds (n->body, (int *) &n->h);
			len = strlen (n->title) + MARGIN_TEXT_X;
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
		}
	}
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
			snprintf (title, sizeof (title) - 1,
				"[ %s ]", n->title);
			W (title);
			(void) G (-g->can->sx, -g->can->sy + 3);
			W (n->body);
		} else {
			char *str = "____";
			if (n->title) {
				int l = strlen (n->title);
				str = n->title;
				if (l > MINIGRAPH_NODE_TITLE_LEN) {
					str += l - MINIGRAPH_NODE_TITLE_LEN;
				}
			}
			snprintf (title, sizeof (title) - 1, "__%s__", str);
			W (title + delta_x);
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
		W ("()");
	}
}

static void normal_RANode_print(const RAGraph *g, const RANode *n, int cur) {
	ut32 center_x = 0, center_y = 0;
	ut32 delta_x = 0, delta_txt_x = 0;
	ut32 delta_y = 0, delta_txt_y = 0;
	char title[TITLE_LEN];
	char *body;
	int x, y;
	char *shortcut;

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
	shortcut = sdb_get (g->db, sdb_fmt (2, "agraph.nodes.%s.shortcut", n->title), 0);
	/* print the title */
	if (cur) {
		snprintf (title, sizeof (title) - 1, "[%s]", n->title);
	} else {
		snprintf (title, sizeof (title) - 1, " %s", n->title);
	}
	if (shortcut) {
		strncat (title, sdb_fmt (2, " ;[g%s]", shortcut), sizeof (title) - strlen (title) - 1);
		free (shortcut);
	}
	if ((delta_x < strlen (title)) && G (n->x + MARGIN_TEXT_X + delta_x, n->y + 1)) {
		W (title + delta_x);
	}

	/* print the body */
	if (g->zoom > ZOOM_DEFAULT) {
		center_x = (g->zoom - ZOOM_DEFAULT) / 10;
		center_y = (g->zoom - ZOOM_DEFAULT) / 30;
		delta_txt_x = R_MIN (delta_x, center_x);
		delta_txt_y = R_MIN (delta_y, center_y);
	}

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
		if (body_y <= body_h && g->zoom < ZOOM_DEFAULT) {
			char *dots = "...";
			if (delta_x < strlen (dots)) {
				dots += delta_x;
				W (dots);
			}
		}
	}

	// TODO: check if node is traced or not and hsow proper color
	// This info must be stored inside RANode* from RCore*
	if (cur) {
		B1 (n->x, n->y, n->w, n->h);
	} else {
		B (n->x, n->y, n->w, n->h);
	}
}

static int **get_crossing_matrix(const RGraph *g,
                                 const struct layer_t layers[],
                                 int maxlayer, int i, int from_up,
                                 int *n_rows) {
	int j, **m, len = layers[i].n_nodes;

	m = R_NEWS0 (int *, len);
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
				for (s = 0; s < j; ++s) {
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
							eprintf ("(WARNING) \"%s\" (%d) or \"%s\" (%d) are not on the right layer (%d)\n",
								ak->title, ak->layer,
								at->title, at->layer,
								i);
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
		for (j = 0; j < layers[i].n_nodes; ++j) {
			const RGraphNode *gj = layers[i].nodes[j];
			const RList *neigh = r_graph_get_neighbours (g, gj);
			const RANode *ak, *aj = get_anode (gj);
			RGraphNode *gk;
			RListIter *itk;

			graph_foreach_anode (neigh, itk, gk, ak) {
				int s;
				for (s = 0; s < layers[i].n_nodes; ++s) {
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

static int layer_sweep(const RGraph *g, const struct layer_t layers[],
                       int maxlayer, int i, int from_up) {
	int **cross_matrix;
	RGraphNode *u, *v;
	const RANode *au, *av;
	int n_rows, j, changed = false;
	int len = layers[i].n_nodes;

	cross_matrix = get_crossing_matrix (g, layers, maxlayer, i, from_up, &n_rows);
	if (!cross_matrix) {
		return false;
	}

	for (j = 0; j < len - 1; ++j) {
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
	for (j = 0; j < layers[i].n_nodes; ++j) {
		RANode *n = get_anode (layers[i].nodes[j]);
		n->pos_in_layer = j;
	}

	for (j = 0; j < n_rows; ++j) {
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

	g->back_edges = r_list_new ();
	cyclic_vis.back_edge = (RGraphEdgeCallback) view_cyclic_edge;
	cyclic_vis.data = g;
	r_graph_dfs (g->graph, &cyclic_vis);

	r_list_foreach (g->back_edges, it, e) {
		RANode *from, *to;
		from = e->from? get_anode (e->from): NULL;
		to = e->to? get_anode (e->to): NULL;
		r_agraph_del_edge (g, from, to);
		r_agraph_add_edge_at (g, to, from, e->nth);
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

static int is_reversed(const RAGraph *g, const RGraphEdge *e) {
	return r_list_find (g->back_edges, e, (RListComparator) find_edge)? true: false;
}

/* add dummy nodes when there are edges that span multiple layers */
static void create_dummy_nodes(RAGraph *g) {
	RGraphVisitor dummy_vis = {
		NULL, NULL, NULL, NULL, NULL, NULL
	};
	const RListIter *it;
	const RGraphEdge *e;

	g->long_edges = r_list_new ();
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
		for (i = 1; i < diff_layer; ++i) {
			RANode *dummy = r_agraph_add_node (g, NULL, NULL);
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

	for (i = 0; i < g->n_layers; ++i) {
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
		--max_changes;

		for (i = 0; i < g->n_layers; ++i) {
			cross_changed |= layer_sweep (g->graph, g->layers, g->n_layers, i, true);
		}
	} while (cross_changed && max_changes);

	max_changes = 4096;

	do {
		cross_changed = false;
		--max_changes;

		for (i = g->n_layers - 1; i >= 0; --i) {
			cross_changed |= layer_sweep (g->graph, g->layers, g->n_layers, i, false);
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
		for (i = aa->pos_in_layer; i < ab->pos_in_layer; ++i) {
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

/* explictly set the distance between two nodes on the same layer */
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

static int is_valid_pos(const RAGraph *g, int l, int pos) {
	return pos >= 0 && pos < g->layers[l].n_nodes;
}

/* computes the set of vertical classes in the graph */
/* if v is an original node, L(v) = { v }
 * if v is a dummy node, L(v) is the set of all the dummies node that belongs
 *      to the same long edge */
static Sdb *compute_vertical_nodes(const RAGraph *g) {
	Sdb *res = sdb_new0 ();
	int i, j;

	for (i = 0; i < g->n_layers; ++i) {
		for (j = 0; j < g->layers[i].n_nodes; ++j) {
			RGraphNode *gn = g->layers[i].nodes[j];
			const RList *Ln = hash_get_rlist (res, gn);
			const RANode *an = get_anode (gn);

			if (!Ln) {
				RList *vert = r_list_new ();
				hash_set (res, gn, vert);
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

	for (i = 0; i < g->n_layers; ++i) {
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
	return (int) a < (int) b;
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
	int dist, v, is_first = true;

	graph_foreach_anode (classes[c], it, gn, an) {
		const RGraphNode *sibling;
		const RANode *sibl_anode;

		sibling = get_sibling (g, an, is_left, true);
		if (!sibling) {
			continue;
		}
		sibl_anode = get_anode (sibling);
		if (sibl_anode->klass == c) {
			continue;
		}
		v = adjust_class_val (g, gn, sibling, res, is_left);
		dist = is_first? v: R_MIN (dist, v);
		is_first = false;
	}

	if (is_first) {
		RList *heap = r_list_new ();
		int len;

		graph_foreach_anode (classes[c], it, gn, an) {
			const RList *neigh = r_graph_all_neighbours (g->graph, gn);
			const RGraphNode *gk;
			const RListIter *itk;
			const RANode *ak;

			graph_foreach_anode (neigh, itk, gk, ak) {
				if (ak->klass < c) {
					r_list_append (heap, (void *) (size_t) (ak->x - an->x));
				}
			}
		}

		len = r_list_length (heap);
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
	Sdb *res, *placed;
	RList **classes;
	int n_classes, i;

	classes = compute_classes (g, v_nodes, is_left, &n_classes);
	if (!classes) {
		return NULL;
	}

	res = sdb_new0 ();
	placed = sdb_new0 ();
	for (i = 0; i < n_classes; ++i) {
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
	for (i = 0; i < n_classes; ++i) {
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
	const RList *nodes;
	Sdb *xminus, *xplus, *vertical_nodes;
	const RGraphNode *gn;
	const RListIter *it;
	RANode *n;

	vertical_nodes = compute_vertical_nodes (g);
	if (!vertical_nodes) {
		return;
	}
	xminus = compute_pos (g, true, vertical_nodes);
	if (!xminus) {
		goto xminus_err;
	}
	xplus = compute_pos (g, false, vertical_nodes);
	if (!xplus) {
		goto xplus_err;
	}

	nodes = r_graph_get_nodes (g->graph);
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

	for (k = an->pos_in_layer + 1; k < g->layers[layer].n_nodes; ++k) {
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
	for (j = 0; j < g->layers[i + d].n_nodes; ++j) {
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

			for (k = wma->pos_in_layer + 1; k < wpa->pos_in_layer; ++k) {
				const RGraphNode *w = g->layers[wma->layer].nodes[k];
				const RANode *aw = get_anode (w);
				if (aw && aw->is_dummy) {
					p &= hash_get_int (P, w);
				}
			}
			if (p) {
				hash_set (D, vm, from_up);
				for (k = vma->pos_in_layer + 1; k < vpa->pos_in_layer; ++k) {
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
	const RList *neigh;
	const RListIter *itk;
	int len;

	neigh = from_up
	        ? r_graph_innodes (g->graph, v)
		: r_graph_get_neighbours (g->graph, v);

	len = r_list_length (neigh);
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
	return a->pos < b->pos;
}

static int RP_listcmp(const struct len_pos_t *a, const struct len_pos_t *b) {
	return a->pos >= b->pos;
}

static void collect_changes(const RAGraph *g, int l, const RGraphNode *b, int from_up, int s, int e, RList *list, int is_left) {
	const RGraphNode *vt = g->layers[l].nodes[e - 1];
	const RGraphNode *vtp = g->layers[l].nodes[s];
	RListComparator lcmp;
	struct len_pos_t *cx;
	int i;

	lcmp = is_left? (RListComparator) RM_listcmp: (RListComparator) RP_listcmp;

	for (i = is_left? s: e - 1;
	     (is_left && i < e) || (!is_left && i >= s);
	     i = is_left? i + 1: i - 1) {
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

	for (i = t - 2; i >= a; --i) {
		const RGraphNode *gv = g->layers[l].nodes[i];
		RANode *av = get_anode (gv);
		if (av && at) {
			av->x = R_MIN (av->x, at->x - dist_nodes (g, gv, vt));
		}
	}

	for (i = t + 1; i < r; ++i) {
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
				for (k = va; k < vr - 1; ++k) {
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
	Sdb *D, *P;
	const RGraphNode *gn;
	const RListIter *itn;
	const RANode *an;

	D = sdb_new0 ();
	if (!D) {
		return;
	}
	P = sdb_new0 ();
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

static void restore_original_edges(const RAGraph *g) {
	const RListIter *it;
	const RGraphEdge *e;

	r_list_foreach (g->long_edges, it, e) {
		RANode *from, *to;
		from = e->from? get_anode (e->from): NULL;
		to = e->to? get_anode (e->to): NULL;
		r_agraph_add_edge_at (g, from, to, e->nth);
	}

	r_list_foreach (g->back_edges, it, e) {
		RANode *from, *to;
		from = e->from? get_anode (e->from): NULL;
		to = e->to? get_anode (e->to): NULL;
		r_agraph_del_edge (g, to, from);
		r_agraph_add_edge_at (g, from, to, e->nth);
	}
}

static void create_edge_from_dummies(const RAGraph *g, RANode *an, RList *toremove) {
	RGraphNode *n = an->gnode;
	RGraphNode *from = r_list_get_n (r_graph_innodes (g->graph, n), 0);
	RANode *a_from = get_anode (from);
	RListIter *(*add_to_list)(RList *, void *) = NULL;
	if (!a_from) {
		return;
	}

	AEdge *e = R_NEW0 (AEdge);
	if (!e) {
		return;
	}
	e->x = r_list_new ();
	e->y = r_list_new ();
	e->is_reversed = an->is_reversed;
	if (e->is_reversed) {
		e->to = a_from;
		add_to_list = r_list_prepend;
		add_to_list (e->x, (void *) (size_t) an->x);
		add_to_list (e->y, (void *) (size_t) a_from->y);
	} else {
		e->from = a_from;
		add_to_list = r_list_append;
	}

	while (an && an->is_dummy) {
		add_to_list (toremove, n);

		add_to_list (e->x, (void *) (size_t) an->x);
		add_to_list (e->y, (void *) (size_t) an->y);

		add_to_list (e->x, (void *) (size_t) an->x);
		add_to_list (e->y, (void *) (size_t)
			(an->y + g->layers[an->layer].height));

		n = r_graph_nth_neighbour (g->graph, n, 0);
		an = get_anode (n);
	}

	if (e->is_reversed) {
		e->from = an;
	} else {
		e->to = an;
	}
	r_list_append (g->edges, e);
}

static void analyze_back_edges(const RAGraph *g, RANode *an) {
	const RList *neigh;
	RListIter *itk;
	RGraphNode *gk;
	RANode *ak;
	int j = 0, i = -1;
	if (!g || !an) {
		return;
	}

	neigh = r_graph_get_neighbours (g->graph, an->gnode);
	/* traverse all neighbours and analyze only the ones that create back
	 * edges. */
	graph_foreach_anode (neigh, itk, gk, ak) {
		RGraphNode *fn, *ln;
		RANode *first, *last;
		const RList *tp;
		AEdge *e;

		i++;
		if (ak->layer > an->layer) {
			continue;
		}
		e = R_NEW0 (AEdge);
		if (!e) {
			return;
		}
		e->is_reversed = true;
		e->from = an;
		e->to = ak;
		e->x = r_list_new ();
		e->y = r_list_new ();

		tp = r_graph_get_neighbours (g->graph, ak->gnode);
		if (r_list_length (tp) > 0) {
			fn = r_list_get_bottom (tp);
			ln = r_list_get_top (tp);
			first = get_anode (fn);
			last = get_anode (ln);

			if (first == an) {
				r_list_append (e->x,
					(void *) (size_t) (an->x - 2 - j));
				r_list_append (e->y, (void *) (size_t) ak->y);
			} else {
				if (last) {
					r_list_append (e->x,
							(void *) (size_t) (last->x + last->w + 2 + j));
				}
				r_list_append (e->y, (void *) (size_t) ak->y);
			}
		}
		r_list_append (g->edges, e);
		j++;
	}
}

static void remove_dummy_nodes(const RAGraph *g) {
	RGraphNode *gn;
	const RListIter *it;
	RList *toremove = r_list_new ();
	int i, j;

	/* traverse all dummy nodes to keep track
	 * of the path long edges should go by.  */
	for (i = 0; i < g->n_layers; ++i) {
		for (j = 0; j < g->layers[i].n_nodes; ++j) {
			RGraphNode *n = g->layers[i].nodes[j];
			RANode *an = get_anode (n);
			if (an->is_dummy && !r_list_contains (toremove, n)) {
				create_edge_from_dummies (g, an, toremove);
			} else if (!an->is_dummy) {
				analyze_back_edges (g, an);
			}
		}
	}

	r_list_foreach (toremove, it, gn) {
		r_graph_del_node (g->graph, gn);
	}

	r_list_free (toremove);
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
	g->edges = r_list_new ();

	remove_cycles (g);
	assign_layers (g);
	create_dummy_nodes (g);
	create_layers (g);
	minimize_crossings (g);

	/* identify row height */
	for (i = 0; i < g->n_layers; i++) {
		int rh = 0;
		int rw = 0;
		for (j = 0; j < g->layers[i].n_nodes; ++j) {
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

	/* x-coordinate assignment: algorithm based on:
	 * A Fast Layout Algorithm for k-Level Graphs
	 * by C. Buchheim, M. Junger, S. Leipert */
	place_dummies (g);
	place_original (g);

	switch (g->layout) {
	default:
	case 0: // vertical layout
		/* vertical align */
		for (i = 0; i < g->n_layers; ++i) {
			for (j = 0; j < g->layers[i].n_nodes; ++j) {
				RANode *n = get_anode (g->layers[i].nodes[j]);
				n->y = 1;
				for (k = 0; k < n->layer; ++k) {
					n->y += g->layers[k].height + VERTICAL_NODE_SPACING;
				}
				if (g->is_tiny) {
					n->y = n->layer;
				}
			}
		}
		/* finalize x coordinate */
		for (i = 0; i < g->n_layers; ++i) {
			for (j = 0; j < g->layers[i].n_nodes; ++j) {
				RANode *n = get_anode (g->layers[i].nodes[j]);
				n->x -= n->w / 2;
				if (g->is_tiny) {
					n->x /= 8;
				}
			}
		}
		break;
	/* experimental */
	case 1: // horizontal layout
		/* vertical align */
		for (i = 0; i < g->n_layers; i++) {
			for (j = 0; j < g->layers[i].n_nodes; j++) {
				RANode *n = get_anode (g->layers[i].nodes[j]);
				n->x = 1;
				for (k = 0; k < n->layer; k++) {
					n->x += g->layers[k].width + HORIZONTAL_NODE_SPACING;
				}
			}
		}
		/* finalize x coordinate */
		for (i = 0; i < g->n_layers; i++) {
			for (j = 0; j < g->layers[i].n_nodes; j++) {
				RANode *n = get_anode (g->layers[i].nodes[j]);
				n->y = 1;
				for (k = 0; k < j; k++) {
					RANode *m = get_anode (g->layers[i].nodes[k]);
					n->y += m->h + VERTICAL_NODE_SPACING;
				}
			}
		}
		break;
	}
	restore_original_edges (g);
	remove_dummy_nodes (g);

	/* free all temporary structures used during layout */
	for (i = 0; i < g->n_layers; ++i) {
		free (g->layers[i].nodes);
	}
	free (g->layers);
	r_list_free (g->long_edges);
	r_list_free (g->back_edges);
}

static char *get_body(RCore *core, ut64 addr, int size, int opts) {
	char *body;
	RConfigHold *hc = r_config_hold_new (core->config);
	if (!hc) {
		return NULL;
	}
	r_config_save_num (hc, "asm.fcnlines", "asm.lines", "asm.bytes",
		"asm.cmtcol", "asm.marks", "asm.marks", "asm.offset",
		"asm.comments", "asm.cmtright", NULL);
	const bool o_comments = r_config_get_i (core->config, "graph.comments");
	const bool o_cmtright = r_config_get_i (core->config, "graph.cmtright");
	int o_cursor = core->print->cur_enabled;

	const char *cmd = (opts & BODY_SUMMARY)? "pds": "pD";

	// configure options
	r_config_set_i (core->config, "asm.fcnlines", false);
	r_config_set_i (core->config, "asm.lines", false);
	r_config_set_i (core->config, "asm.cmtcol", 0);
	r_config_set_i (core->config, "asm.marks", false);
	r_config_set_i (core->config, "asm.cmtright", (opts & BODY_SUMMARY) || o_cmtright);
	r_config_set_i (core->config, "asm.comments", (opts & BODY_SUMMARY) || o_comments);
	core->print->cur_enabled = false;

	if (opts & BODY_OFFSETS || opts & BODY_SUMMARY) {
		r_config_set_i (core->config, "asm.offset", true);
		r_config_set_i (core->config, "asm.bytes", true);
	} else {
		r_config_set_i (core->config, "asm.bytes", false);
		r_config_set_i (core->config, "asm.offset", false);
	}
	bool html = r_config_get_i (core->config, "scr.html");
	r_config_set_i (core->config, "scr.html", 0);
	body = r_core_cmd_strf (core,
			"%s %d @ 0x%08"PFMT64x, cmd, size, addr);
	r_config_set_i (core->config, "scr.html", html);

	// restore original options
	core->print->cur_enabled = o_cursor;
	r_config_restore (hc);
	r_config_hold_free (hc);
	return body;
}

static char *get_bb_body(RCore *core, RAnalBlock *b, int opts, RAnalFunction *fcn, bool emu, ut64 saved_gp, ut8 *saved_arena) {
	if (emu) {
		core->anal->gp = saved_gp;
		if (b->parent_reg_arena) {
			r_reg_arena_poke (core->anal->reg, b->parent_reg_arena);
			R_FREE (b->parent_reg_arena);
			ut64 gp = r_reg_getv (core->anal->reg, "gp");
			if (gp) {
				core->anal->gp = gp;
			}
		} else {
			r_reg_arena_poke (core->anal->reg, saved_arena);
		}
	}
	if (b->parent_stackptr != INT_MAX) {
		core->anal->stackptr = b->parent_stackptr;
	}
	char *body = get_body (core, b->addr, b->size, opts);
	if (b->jump != UT64_MAX) {
		if (b->jump > b->addr) {
			RAnalBlock *jumpbb = r_anal_bb_get_jumpbb (fcn, b);
			if (jumpbb) {
				if (emu && core->anal->last_disasm_reg != NULL && !jumpbb->parent_reg_arena) {
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
			RAnalBlock *failbb = r_anal_bb_get_failbb (fcn, b);
			if (failbb) {
				if (emu && core->anal->last_disasm_reg != NULL && !failbb->parent_reg_arena) {
					failbb->parent_reg_arena = r_reg_arena_dup (core->anal->reg, core->anal->last_disasm_reg);
				}
				if (failbb->parent_stackptr == INT_MAX) {
					failbb->parent_stackptr = core->anal->stackptr + b->stackptr;
				}
			}
		}
	}
	return body;
}

static int bbcmp(RAnalBlock *a, RAnalBlock *b) {
	return a->addr - b->addr;
}

static void get_bbupdate(RAGraph *g, RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *iter;
	bool emu = r_config_get_i (core->config, "asm.emu");
	ut64 saved_gp = core->anal->gp;
	ut8 *saved_arena = NULL;
	int saved_stackptr = core->anal->stackptr;
	char *shortcut = 0;
	int shortcuts = 0;
	core->keep_asmqjmps = false;

	if (emu) {
		saved_arena = r_reg_arena_peek (core->anal->reg);
	}
	if (!fcn) {
		R_FREE (saved_arena);
		return;
	}
	r_list_sort (fcn->bbs, (RListComparator) bbcmp);

	shortcuts = r_config_get_i (core->config, "graph.nodejmps");
	r_list_foreach (fcn->bbs, iter, bb) {
		RANode *node;
		char *title, *body;

		if (bb->addr == UT64_MAX) {
			continue;
		}
		body = get_bb_body (core, bb, mode2opts (g), fcn, emu, saved_gp, saved_arena);
		title = get_title (bb->addr);

		if (shortcuts) {
			shortcut = r_core_add_asmqjmp (core, bb->addr);
			if (shortcut) {
				sdb_set (g->db, sdb_fmt (2, "agraph.nodes.%s.shortcut", title), shortcut, 0);
				free (shortcut);
			}
		}
		node = r_agraph_get_node (g, title);
		if (node) {
			free (node->body);
			node->body = body;
		} else {
			free (body);
		}
		free (title);
		core->keep_asmqjmps = true;
	}

	if (emu) {
		core->anal->gp = saved_gp;
		if (saved_arena) {
			r_reg_arena_poke (core->anal->reg, saved_arena);
			R_FREE (saved_arena);
		}
	}
	core->anal->stackptr = saved_stackptr;
}

/* build the RGraph inside the RAGraph g, starting from the Basic Blocks */
static int get_bbnodes(RAGraph *g, RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *iter;
	char *shortcut = NULL;
	int shortcuts = 0;
	bool emu = r_config_get_i (core->config, "asm.emu");
	int ret = false;
	ut64 saved_gp = core->anal->gp;
	ut8 *saved_arena = NULL;
	int saved_stackptr = core->anal->stackptr;
	core->keep_asmqjmps = false;

	if (!fcn) {
		return false;
	}
	if (emu) {
		saved_arena = r_reg_arena_peek (core->anal->reg);
	}
	r_list_sort (fcn->bbs, (RListComparator) bbcmp);

	core->keep_asmqjmps = false;
	r_list_foreach (fcn->bbs, iter, bb) {
		RANode *node;
		char *title, *body;

		if (bb->addr == UT64_MAX) {
			continue;
		}
		body = get_bb_body (core, bb, mode2opts (g), fcn, emu, saved_gp, saved_arena);
		title = get_title (bb->addr);

		node = r_agraph_add_node (g, title, body);
		shortcuts = r_config_get_i (core->config, "graph.nodejmps");

		if (shortcuts) {
			shortcut = r_core_add_asmqjmp (core, bb->addr);
			if (shortcut) {
				sdb_set (g->db, sdb_fmt (2, "agraph.nodes.%s.shortcut", title), shortcut, 0);
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
		RANode *u, *v;
		char *title;

		if (bb->addr == UT64_MAX) {
			continue;
		}

		title = get_title (bb->addr);
		u = r_agraph_get_node (g, title);
		free (title);
		if (bb->jump != UT64_MAX) {
			title = get_title (bb->jump);
			v = r_agraph_get_node (g, title);
			free (title);
			r_agraph_add_edge (g, u, v);
		}
		if (bb->fail != UT64_MAX) {
			title = get_title (bb->fail);
			v = r_agraph_get_node (g, title);
			free (title);
			r_agraph_add_edge (g, u, v);
		}
		if (bb->switch_op) {
			RListIter *it;
			RAnalCaseOp *cop;
			r_list_foreach (bb->switch_op->cases, it, cop) {
				title = get_title (cop->addr);
				v = r_agraph_get_node (g, title);
				free (title);
				r_agraph_add_edge (g, u, v);
			}
		}
	}

	ret = true;

cleanup:
	if (emu) {
		core->anal->gp = saved_gp;
		if (saved_arena) {
			r_reg_arena_poke (core->anal->reg, saved_arena);
			R_FREE (saved_arena);
		}
	}
	core->anal->stackptr = saved_stackptr;
	return ret;
}

/* build the RGraph inside the RAGraph g, starting from the Call Graph
 * information */
static int get_cgnodes(RAGraph *g, RCore *core, RAnalFunction *fcn) {
#if FCN_OLD
	RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset, 0);
	RANode *node, *fcn_anode;
	RListIter *iter;
	RAnalRef *ref;
	char *title, *body;

	if (!f) {
		return false;
	}
	if (!fcn) {
		fcn = f;
	}

	r_core_seek (core, f->addr, 1);

	title = get_title (fcn->addr);
	fcn_anode = r_agraph_add_node (g, title, "");

	free (title);
	if (!fcn_anode) {
		return false;
	}

	fcn_anode->x = 10;
	fcn_anode->y = 3;

	r_list_foreach (fcn->refs, iter, ref) {
		/* XXX: something is broken, why there are duplicated
		 *      nodes here?! goto check fcn->refs!! */
		/* avoid dups wtf */
		title = get_title (ref->addr);
		if (r_agraph_get_node (g, title) != NULL) {
			continue;
		}
		free (title);

		int size = 0;
		RAnalBlock *bb = r_anal_bb_from_offset (core->anal, ref->addr);
		if (bb) {
			size = bb->size;
		}

		body = get_body (core, ref->addr, size, mode2opts (g));
		title = get_title (ref->addr);

		node = r_agraph_add_node (g, title, body);
		if (!node) {
			return false;
		}

		free (title);
		free (body);

		node->x = 10;
		node->y = 10;

		r_agraph_add_edge (g, fcn_anode, node);
	}
#else
	eprintf ("Must be sdbized\n");
#endif

	return true;
}

static int reload_nodes(RAGraph *g, RCore *core, RAnalFunction *fcn) {
	int is_c = g->is_callgraph;
	return is_c? get_cgnodes (g, core, fcn): get_bbnodes (g, core, fcn);
}

static void update_seek(RConsCanvas *can, RANode *n, int force) {
	int x, y, w, h;
	int doscroll = false;

	if (!n) {
		return;
	}
	x = n->x + can->sx;
	y = n->y + can->sy;
	w = can->w;
	h = can->h;

	doscroll = force || y < 0 || y + 5 > h || x + 5 > w || x + n->w + 5 < 0;

	if (doscroll) {
		can->sx = -n->x - n->w / 2 + w / 2;
		can->sy = -n->y - n->h / 8 + h / 4;
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
	int default_v = is_next? INT_MIN: INT_MAX;
	int start_y = acur? acur->y: default_v;
	int start_x = acur? acur->x: default_v;

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
			} else if ((is_next && resn->y == n->y && resn->x > n->x) ||
			           (!is_next && resn->y == n->y && resn->x < n->x)) {
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
		if (ak->x < g->x) {
			g->x = ak->x;
		}
		if (ak->y < g->y) {
			g->y = ak->y;
			min_gn = ak;
		}
		if (ak->x + ak->w > max_x) {
			max_x = ak->x + ak->w;
		}
		if (ak->y + ak->h > max_y) {
			max_y = ak->y + ak->h;
			max_gn = ak;
		}
	}
	r_cons_break_push (NULL, NULL);
	/* while calculating the graph size, take into account long edges */
	r_list_foreach (g->edges, it, e) {
		RListIter *kt;
		void *vv;
		int v;
		if (r_cons_is_breaked ()) {
			break;
		}
		r_list_foreach (e->x, kt, vv) {
			if (r_cons_is_breaked ()) {
				break;
			}
			v = (int) (size_t) vv;
			if (v < g->x) {
				g->x = v;
			}
			if (v + 1 > max_x) {
				max_x = v + 1;
			}
		}
		r_list_foreach (e->y, kt, vv) {
			if (r_cons_is_breaked ()) {
				break;
			}
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

static void agraph_set_layout(RAGraph *g, bool is_interactive) {
	RListIter *it;
	RGraphNode *n;
	RANode *a;

	set_layout (g);

	update_graph_sizes (g);
	graph_foreach_anode (r_graph_get_nodes (g->graph), it, n, a) {
		const char *k;
		k = sdb_fmt (1, "agraph.nodes.%s.x", a->title);
		sdb_num_set (g->db, k, rebase (g, a->x), 0);
		k = sdb_fmt (1, "agraph.nodes.%s.y", a->title);
		sdb_num_set (g->db, k, rebase (g, a->y), 0);
		k = sdb_fmt (1, "agraph.nodes.%s.w", a->title);
		sdb_num_set (g->db, k, a->w, 0);
		k = sdb_fmt (1, "agraph.nodes.%s.h", a->title);
		sdb_num_set (g->db, k, a->h, 0);
	}
}

/* set the willing to center the screen on a particular node */
static void agraph_update_seek(RAGraph *g, RANode *n, int force) {
	g->update_seek_on = n;
	g->force_update_seek = force;
}

static void agraph_print_node(const RAGraph *g, RANode *n) {
	const int cur = g->curnode && get_anode (g->curnode) == n;
	if (g->is_tiny) {
		tiny_RANode_print (g, n, cur);
	} else if (is_mini (g) || n->is_mini) {
		mini_RANode_print (g, n, cur, is_mini (g));
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

static int find_ascii_edge(const AEdge *a, const AEdge *b) {
	return a->from == b->from && a->to == b->to? 0: 1;
}

/* print an edge between two nodes.
 * nth: specifies if the edge is the true(1)/false(2) branch or if it's the
 *      only edge for that node(0), so that a different style will be applied
 *      to the drawn line */
static void agraph_print_edge(const RAGraph *g, RANode *a, RANode *b, int nth) {
	int x, y, x2, y2;
	int xinc;
	RListIter *it;
	AEdge e, *edg = NULL;
	int is_first = true;
	RCanvasLineStyle style;

	xinc = 4 + 2 * (nth + 1);
	x = a->x + xinc;
	y = a->y + a->h;
	if (nth > 1) {
		nth = 1;
	}

	switch (nth) {
	case 0: style.color = LINE_TRUE; break;
	case 1: style.color = LINE_FALSE; break;
	case -1: style.color = LINE_UNCJMP; break;
	default: style.color = LINE_NONE; break;
	}
	style.symbol = style.color;

	e.from = a;
	e.to = b;
	it = r_list_find (g->edges, &e, (RListComparator) find_ascii_edge);

	switch (g->layout) {
	case 0:
	default:
		it = r_list_find (g->edges, &e, (RListComparator) find_ascii_edge);
		if (it) {
			int i, len;

			edg = r_list_iter_get_data (it);
			len = r_list_length (edg->x);

			for (i = 0; i < len; ++i) {
				x2 = (int) (size_t) r_list_get_n (edg->x, i);
				y2 = (int) (size_t) r_list_get_n (edg->y, i) - 1;

				if (is_first && nth == 0 && x2 > x) {
					xinc += 4;
					x += 4;
				}
				r_cons_canvas_line (g->can, x, y, x2, y2, &style);

				x = x2;
				y = y2;
				style.symbol = LINE_NONE;
				is_first = false;
			}
		}
		x2 = b->x + xinc;
		y2 = b->y - 1;
		if (is_first && nth == 0 && x2 > x) {
			xinc += 4;
			x += 4;
		}
		r_cons_canvas_line (g->can, x, y, x2, y2, &style);
		break;
	case 1:
		x = a->x + a->w;
		y = a->y + (a->h / 2) + nth;
		if (it) {
			int i, len;
			edg = r_list_iter_get_data (it);
			len = r_list_length (edg->x);

			for (i = 0; i < len; i++) {
				// r_cons_canvas_line (g->can, x, y, x2, y2, &style);
				x = a->x + a->w;
				y = a->y + (a->h / 2);
				style.symbol = LINE_NONE;
				is_first = false;
			}
		}
		x2 = b->x - 1;
		y2 = b->y + (b->h / 2);
		r_cons_canvas_line (g->can, x, y, x2, y2, &style);
		break;
	}
}

static void agraph_print_edges(const RAGraph *g) {
	const RList *nodes = r_graph_get_nodes (g->graph);
	RGraphNode *gn, *gv;
	RListIter *it, *itn;
	RANode *u, *v;

	graph_foreach_anode (nodes, it, gn, u) {
		const RList *neighbours = r_graph_get_neighbours (g->graph, gn);
		const int exit_edges = r_list_length (neighbours);
		int nth = 0;

		graph_foreach_anode (neighbours, itn, gv, v) {
			int cur_nth = nth;
			if (g->is_callgraph) {
				/* hack: we don't support more than two exit edges from a node
				 * yet, so set nth to zero, to make every edge appears as the
				 * "true" edge of the node */
				cur_nth = 0;
			} else if (exit_edges == 1) {
				cur_nth = -1;
			}
			agraph_print_edge (g, u, v, cur_nth);
			nth++;
		}
	}
}

static void agraph_toggle_callgraph(RAGraph *g) {
	g->is_callgraph = !g->is_callgraph;
	g->need_reload_nodes = true;
	g->force_update_seek = true;
}

static void agraph_set_zoom(RAGraph *g, int v) {
	g->is_tiny = false;
	if (v == 0) {
		g->mode = R_AGRAPH_MODE_MINI;
	} else if (v < 0) {
		g->mode = R_AGRAPH_MODE_TINY;
		g->is_tiny = true;
	} else {
		g->mode = R_AGRAPH_MODE_NORMAL;
	}
	g->zoom = R_MAX (-10, v);
	g->need_update_dim = true;
	g->need_set_layout = true;
}

/* reload all the info in the nodes, depending on the type of the graph
 * (callgraph, CFG, etc.), set the default layout for these nodes and center
 * the screen on the selected one */
static int agraph_reload_nodes(RAGraph *g, RCore *core, RAnalFunction *fcn) {
	r_agraph_reset (g);
	return reload_nodes (g, core, fcn);
}

static void follow_nth(RAGraph *g, int nth) {
	const RGraphNode *cn = r_graph_nth_neighbour (g->graph, g->curnode, nth);
	if (cn) {
		r_agraph_set_curnode (g, get_anode (cn));
	}
}

#if GRAPH_MERGE_FEATURE
#define K_NEIGHBOURS(x) (sdb_fmt (2, "agraph.nodes.%s.neighbours", x->title))
static void agraph_merge_child(RAGraph *g, int idx) {
	const RGraphNode *nn = r_graph_nth_neighbour (g->graph, g->curnode, idx);
	const RGraphNode *cn = g->curnode;
	if (cn && nn) {
		RANode *ann = get_anode (nn);
		RANode *acn = get_anode (cn);
		acn->body = r_str_append (acn->body, ann->title);
		acn->body = r_str_append (acn->body, "\n");
		acn->body = r_str_append (acn->body, ann->body);
		/* remove node from the graph */
		acn->h += ann->h - 3;
		free (ann->body);
		// TODO: do not merge nodes if those have edges targeting them
		// TODO: Add children neighbours to current one
		// nn->body
		// r_agraph_set_curnode (g, get_anode (cn));
		// agraph_refresh (grd);
		// r_agraph_add_edge (g, from, to);
		char *neis = sdb_get (g->db, K_NEIGHBOURS (ann), 0);
		sdb_set_owned (g->db, K_NEIGHBOURS (ann), neis, 0);
		r_agraph_del_node (g, ann->title);
		agraph_print_nodes (g);
		agraph_print_edges (g);
	}
	// agraph_update_seek (g, get_anode (g->curnode), false);
}
#endif

static void agraph_toggle_tiny (RAGraph *g) {
	g->is_tiny = !g->is_tiny;
	g->need_update_dim = 1;
	agraph_refresh (r_cons_singleton ()->event_data);
	agraph_set_layout ((RAGraph *) g, r_cons_singleton ()->is_interactive);
}

static void agraph_toggle_mini(RAGraph *g) {
	RANode *n = get_anode (g->curnode);
	if (n) {
		n->is_mini = !n->is_mini;
	}
	g->need_update_dim = 1;
	agraph_refresh (r_cons_singleton ()->event_data);
	agraph_set_layout ((RAGraph *) g, r_cons_singleton ()->is_interactive);
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
	r_agraph_set_curnode (g, get_anode (find_near_of (g, g->curnode, true)));
	agraph_update_seek (g, get_anode (g->curnode), false);
}

/* seek the previous node in visual order */
static void agraph_prev_node(RAGraph *g) {
	r_agraph_set_curnode (g, get_anode (find_near_of (g, g->curnode, false)));
	agraph_update_seek (g, get_anode (g->curnode), false);
}

static void agraph_update_title(RAGraph *g, RAnalFunction *fcn) {
	const char *mode_str = g->is_callgraph? mode2str (g, "CG"): mode2str (g, "BB");
	char *new_title = r_str_newf (
		"[0x%08"PFMT64x "]> VV @ %s (nodes %d edges %d zoom %d%%) %s mouse:%s movements-speed:%d",
		fcn->addr, fcn->name, g->graph->n_nodes, g->graph->n_edges,
		g->zoom, mode_str, mousemodes[mousemode], g->movspeed);
	r_agraph_set_title (g, new_title);
	r_str_free (new_title);
}

/* look for any change in the state of the graph
 * and update what's necessary */
static int check_changes(RAGraph *g, int is_interactive,
                         RCore *core, RAnalFunction *fcn) {
	int oldpos[2] = {
		0, 0
	};
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
	if (fcn) {
		agraph_update_title (g, fcn);
	}
	if (g->need_update_dim || g->need_reload_nodes || !is_interactive) {
		update_node_dimension (g->graph, is_mini (g), g->zoom);
	}
	if (g->need_set_layout || g->need_reload_nodes || !is_interactive) {
		agraph_set_layout (g, is_interactive);
	}
	if (core) {
		ut64 off = r_core_anal_get_bbaddr (core, core->offset);
		char *title = get_title (off);
		RANode *cur_anode = get_anode (g->curnode);
		if (fcn && ((is_interactive && !cur_anode) ||
				(cur_anode && strcmp (cur_anode->title, title) != 0))) {
			g->update_seek_on = r_agraph_get_node (g, title);
			if (g->update_seek_on) {
				r_agraph_set_curnode (g, g->update_seek_on);
				g->force_update_seek = true;
			}
		}
		free (title);
		g->can->color = r_config_get_i (core->config, "scr.color");
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

static int agraph_print(RAGraph *g, int is_interactive, RCore *core, RAnalFunction *fcn) {
	int h, w = r_cons_get_size (&h);
	int ret = check_changes (g, is_interactive, core, fcn);
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
	w = is_interactive? w: g->w;
	r_cons_canvas_resize (g->can, w, h);
	// r_cons_canvas_clear (g->can);
	if (!is_interactive) {
		g->can->sx = -g->x;
		g->can->sy = -g->y + 1;
	}

	if (!g->is_tiny) {
		agraph_print_edges (g);
	}
	agraph_print_nodes (g);

	/* print the graph title */
	(void) G (-g->can->sx, -g->can->sy);
	W (g->title);
	if (is_interactive && g->title) {
		int title_len = strlen (g->title);
		r_cons_canvas_fill (g->can, -g->can->sx + title_len, -g->can->sy,
			w - title_len, 1, ' ', true);
	}

	r_cons_canvas_print_region (g->can);

	if (is_interactive) {
		const char *cmdv = r_config_get (core->config, "cmd.gprompt");
		r_cons_strcat (Color_RESET);
		if (cmdv && *cmdv) {
			r_cons_gotoxy (0, 0);
			r_cons_fill_line ();
			r_cons_gotoxy (0, 0);
			r_core_cmd0 (core, cmdv);
		}
		r_cons_flush ();
	}
	return true;
}

static int agraph_refresh(struct agraph_refresh_data *grd) {
	RCore *core = grd->core;
	RAGraph *g = grd->g;
	RAnalFunction *f, **fcn = grd->fcn;

	// allow to change the current function during debugging
	if (g->is_instep && core->io->debug) {
		// seek only when the graph node changes
		const char *pc = r_reg_get_name (core->dbg->reg, R_REG_NAME_PC);
		RRegItem *r = r_reg_get (core->dbg->reg, pc, -1);
		ut64 addr = r_reg_get_value (core->dbg->reg, r);
		RANode *acur = get_anode (g->curnode);

		addr = r_core_anal_get_bbaddr (core, addr);
		char *title = get_title (addr);

		if (!acur || strcmp (acur->title, title) != 0) {
			r_core_cmd0 (core, "sr PC");
		}
		free (title);
		g->is_instep = false;
	}

	if (fcn) {
		f = r_anal_get_fcn_in (core->anal, core->offset, 0);
		if (!f) {
			r_cons_message ("Not in a function. Type 'df' to define it here");
			return 0;
		}
		if (f && f != *fcn) {
			*fcn = f;
			g->need_reload_nodes = true;
			g->force_update_seek = true;
		}
	}

	return agraph_print (g, grd->fs, core, fcn != NULL? *fcn: NULL);
}

static void agraph_toggle_speed(RAGraph *g, RCore *core) {
	int alt = r_config_get_i (core->config, "graph.scroll");
	g->movspeed = g->movspeed == DEFAULT_SPEED? alt: DEFAULT_SPEED;
}

static void agraph_init(RAGraph *g) {
	g->is_callgraph = false;
	g->is_instep = false;
	g->need_reload_nodes = true;
	g->force_update_seek = true;
	g->color_box = Color_RESET;
	g->color_box2 = Color_BLUE; // selected node
	g->color_box3 = Color_MAGENTA;
	g->graph = r_graph_new ();
	g->nodes = sdb_new0 ();
	g->zoom = ZOOM_DEFAULT;
	g->movspeed = DEFAULT_SPEED; // r_config_get_i (g->core->config, "graph.scroll");
	g->db = sdb_new0 ();
}

static void free_anode(RANode *n) {
	free (n->title);
	free (n->body);
}

static int free_anode_cb(void *user UNUSED, const char *k UNUSED, const char *v) {
	RANode *n = (RANode *) (size_t) sdb_atoi (v);
	if (!n) {
		return 0;
	}
	free_anode (n);
	return 1;
}

static void agraph_free_nodes(const RAGraph *g) {
	sdb_foreach (g->nodes, (SdbForeachCallback) free_anode_cb, NULL);
	sdb_free (g->nodes);
}

static void sdb_set_enc(Sdb *db, const char *key, const char *v, ut32 cas) {
	char *estr = sdb_encode ((const void *) v, -1);
	sdb_set (db, key, estr, cas);
	free (estr);
}

static void agraph_sdb_init(const RAGraph *g) {
	sdb_bool_set (g->db, "agraph.is_callgraph", g->is_callgraph, 0);
	sdb_set_enc (g->db, "agraph.color_box", g->color_box, 0);
	sdb_set_enc (g->db, "agraph.color_box2", g->color_box2, 0);
	sdb_set_enc (g->db, "agraph.color_box3", g->color_box3, 0);
	sdb_set_enc (g->db, "agraph.color_true", g->color_true, 0);
	sdb_set_enc (g->db, "agraph.color_false", g->color_false, 0);
}

R_API Sdb *r_agraph_get_sdb(RAGraph *g) {
	g->need_update_dim = true;
	g->need_set_layout = true;
	check_changes (g, false, NULL, NULL);
	return g->db;
}

R_API void r_agraph_print(RAGraph *g) {
	agraph_print (g, false, NULL, NULL);
	if (g->graph->n_nodes > 0) {
		r_cons_newline ();
	}
}

R_API void r_agraph_set_title(RAGraph *g, const char *title) {
	free (g->title);
	g->title = title? strdup (title): NULL;
	sdb_set (g->db, "agraph.title", g->title, 0);
}

R_API RANode *r_agraph_add_node(const RAGraph *g, const char *title, const char *body) {
	RANode *res = r_agraph_get_node (g, title);
	if (res) {
		return res;
	}
	res = R_NEW0 (RANode);
	if (!res) {
		return NULL;
	}
	res->title = title? strdup (title): strdup ("");
	res->body = body? strdup (body): strdup ("");
	res->layer = -1;
	res->pos_in_layer = -1;
	res->is_dummy = false;
	res->is_reversed = false;
	res->klass = -1;
	res->gnode = r_graph_add_node (g->graph, res);
	sdb_num_set (g->nodes, title, (ut64) (size_t) res, 0);
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
		s = sdb_fmt (1, "base64:%s", estr);
		free (estr);
		free (b);
		sdb_set (g->db, sdb_fmt (2, "agraph.nodes.%s.body", res->title), s, 0);
	}
	return res;
}

R_API bool r_agraph_del_node(const RAGraph *g, const char *title) {
	RANode *an, *res = r_agraph_get_node (g, title);
	const RList *innodes;
	RGraphNode *gn;
	RListIter *it;

	if (!res) {
		return false;
	}
	sdb_set (g->nodes, title, NULL, 0);
	sdb_array_remove (g->db, "agraph.nodes", res->title, 0);
	sdb_set (g->db, sdb_fmt (2, "agraph.nodes.%s", res->title), NULL, 0);
	sdb_set (g->db, sdb_fmt (2, "agraph.nodes.%s.body", res->title), 0, 0);
	sdb_set (g->db, sdb_fmt (2, "agraph.nodes.%s.x", res->title), NULL, 0);
	sdb_set (g->db, sdb_fmt (2, "agraph.nodes.%s.y", res->title), NULL, 0);
	sdb_set (g->db, sdb_fmt (2, "agraph.nodes.%s.w", res->title), NULL, 0);
	sdb_set (g->db, sdb_fmt (2, "agraph.nodes.%s.h", res->title), NULL, 0);
	sdb_set (g->db, sdb_fmt (2, "agraph.nodes.%s.neighbours", res->title), NULL, 0);

	innodes = r_graph_innodes (g->graph, res->gnode);
	graph_foreach_anode (innodes, it, gn, an) {
		const char *key = sdb_fmt (2, "agraph.nodes.%s.neighbours", an->title);
		sdb_array_remove (g->db, key, res->title, 0);
	}

	r_graph_del_node (g->graph, res->gnode);
	res->gnode = NULL;

	free_anode (res);
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
	struct g_cb u;
	u.node_cb = cb;
	u.data = user;
	sdb_foreach (g->nodes, (SdbForeachCallback) user_node_cb, &u);
}

R_API void r_agraph_foreach_edge(RAGraph *g, RAEdgeCallback cb, void *user) {
	struct g_cb u;
	u.graph = g;
	u.edge_cb = cb;
	u.data = user;
	sdb_foreach (g->nodes, (SdbForeachCallback) user_edge_cb, &u);
}

R_API RANode *r_agraph_get_first_node(const RAGraph *g) {
	const RList *l = r_graph_get_nodes (g->graph);
	RGraphNode *rgn = r_list_first (l);
	return get_anode (rgn);
}

R_API RANode *r_agraph_get_node(const RAGraph *g, const char *title) {
	return (RANode *) (size_t) sdb_num_get (g->nodes, title, NULL);
}

R_API void r_agraph_add_edge(const RAGraph *g, RANode *a, RANode *b) {
	if (!g || !a || !b) {
		return;
	}
	r_graph_add_edge (g->graph, a->gnode, b->gnode);
	if (a->title && b->title) {
		char *k = sdb_fmt (1, "agraph.nodes.%s.neighbours", a->title);
		sdb_array_add (g->db, k, b->title, 0);
	}
}

R_API void r_agraph_add_edge_at(const RAGraph *g, RANode *a, RANode *b, int nth) {
	if (!g || !a || !b) {
		return;
	}
	if (a->title && b->title) {
		char *k = sdb_fmt (1, "agraph.nodes.%s.neighbours", a->title);
		sdb_array_insert (g->db, k, nth, b->title, 0);
	}
	r_graph_add_edge_at (g->graph, a->gnode, b->gnode, nth);
}

R_API void r_agraph_del_edge(const RAGraph *g, RANode *a, RANode *b) {
	if (!g || !a || !b) {
		return;
	}
	if (a->title && b->title) {
		char *k = sdb_fmt (1, "agraph.nodes.%s.neighbours", a->title);
		sdb_array_remove (g->db, k, b->title, 0);
	}
	r_graph_del_edge (g->graph, a->gnode, b->gnode);
}

R_API void r_agraph_reset(RAGraph *g) {
	r_graph_reset (g->graph);
	agraph_free_nodes (g);
	r_agraph_set_title (g, NULL);
	sdb_reset (g->db);
	r_list_free (g->edges);

	g->nodes = sdb_new0 ();
	g->update_seek_on = NULL;
	g->x = g->y = g->w = g->h = 0;
	agraph_sdb_init (g);
	g->edges = r_list_new ();
	g->curnode = NULL;
}

R_API void r_agraph_free(RAGraph *g) {
	if (g) {
		r_graph_free (g->graph);
		r_list_free (g->edges);
		agraph_free_nodes (g);
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
	r_line_set_prompt ("[offset]> ");
	strcpy (buf, "s ");
	if (r_cons_fgets (buf + 2, sizeof (buf) - 3, 0, NULL) > 0) {
		if (buf[2] == '.') {
			buf[1] = '.';
		}
		r_core_cmd0 (core, buf);
	}
}

static void goto_asmqjmps(RAGraph *g, RCore *core) {
	const char *h = "[Fast goto call/jmp]> ";
	char obuf[R_CORE_ASMQJMPS_LEN_LETTERS + 1];
	int rows, i = 0;
	bool cont;

	r_cons_get_size (&rows);
	r_cons_gotoxy (0, rows);
	r_cons_printf (Color_RESET);
	r_cons_printf (h);
	r_cons_flush ();
	r_cons_clear_line (0);
	r_cons_gotoxy (strlen (h) + 1, rows);

	do {
		char ch = r_cons_readchar ();
		obuf[i++] = ch;
		r_cons_printf ("%c", ch);
		r_cons_flush ();
		cont = isalpha ((ut8) ch) && !islower ((ut8) ch);
	} while (i < R_CORE_ASMQJMPS_LEN_LETTERS && cont);

	obuf[i] = '\0';
	ut64 addr = r_core_get_asmqjmps (core, obuf);
	if (addr != UT64_MAX) {
		char *title = get_title (addr);
		RANode *addr_node = r_agraph_get_node (g, title);
		if (addr_node) {
			r_agraph_set_curnode (g, addr_node);
			agraph_update_seek (g, addr_node, true);
		} else {
			r_io_sundo_push (core->io, core->offset, 0);
			r_core_seek (core, addr, 0);
		}
		free (title);
	}
}

static void seek_to_node(RANode *n, RCore *core) {
	ut64 off = r_core_anal_get_bbaddr (core, core->offset);
	char *title = get_title (off);

	if (strcmp (title, n->title) != 0) {
		char *cmd = r_str_newf ("s %s", n->title);
		r_core_cmd0 (core, cmd);
		free (cmd);
	}
	free (title);
}

static void graph_single_step_in(RCore *core, RAGraph *g) {
	if (r_config_get_i (core->config, "cfg.debug")) {
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
	if (r_config_get_i (core->config, "cfg.debug")) {
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

R_API int r_core_visual_graph(RCore *core, RAGraph *g, RAnalFunction *_fcn, int is_interactive) {
	int o_asmqjmps_letter = core->is_asmqjmps_letter;
	int o_scrinteractive = r_config_get_i (core->config, "scr.interactive");
	int o_vmode = core->vmode;
	int exit_graph = false, is_error = false;
	struct agraph_refresh_data *grd;
	int okey, key, wheel;
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

	int h, w = r_cons_get_size (&h);
	can = r_cons_canvas_new (w, h);
	if (!can) {
		eprintf (
			"Cannot create RCons.canvas context. Invalid screen "
			"size? See scr.columns + scr.rows\n");
		r_config_hold_free (hc);
		return false;
	}
	can->linemode = r_config_get_i (core->config, "graph.linemode");
	can->color = r_config_get_i (core->config, "scr.color");

	r_config_save_num (hc, "asm.cmtright", NULL);
	if (!g) {
		graph_allocated = true;
		fcn = _fcn? _fcn: r_anal_get_fcn_in (core->anal, core->offset, 0);
		if (!fcn) {
			eprintf ("No function in current seek\n");
			r_config_restore (hc);
			r_config_hold_free (hc);
			r_cons_canvas_free (can);
			return false;
		}
		g = r_agraph_new (can);
		if (!g) {
			r_cons_canvas_free (can);
			r_config_restore (hc);
			r_config_hold_free (hc);
			return false;
		}
		g->is_tiny = is_interactive == 2;
		g->layout = r_config_get_i (core->config, "graph.layout");
	} else {
		o_can = g->can;
	}
	r_config_set_i (core->config, "scr.interactive", false);
	g->can = can;
	g->movspeed = r_config_get_i (core->config, "graph.scroll");
	g->on_curnode_change = (RANodeCallback) seek_to_node;
	g->on_curnode_change_data = core;
	bool asm_comments = r_config_get_i (core->config, "asm.comments");
	r_config_set (core->config, "asm.comments",
		r_str_bool (r_config_get_i (core->config, "graph.comments")));

	/* we want letters as shortcuts for call/jmps */
	core->is_asmqjmps_letter = true;
	core->vmode = true;

	grd = R_NEW0 (struct agraph_refresh_data);
	if (!grd) {
		r_cons_canvas_free (can);
		r_config_restore (hc);
		r_config_hold_free (hc);
		r_agraph_free (g);
		return false;
	}
	grd->g = g;
	grd->fs = is_interactive == 1;
	grd->core = core;
	grd->fcn = fcn != NULL? &fcn: NULL;
	ret = agraph_refresh (grd);
	if (!ret || is_interactive != 1) {
		r_cons_newline ();
		exit_graph = true;
		is_error = !ret;
	}

	core->cons->event_data = grd;
	core->cons->event_resize = (RConsEvent) agraph_refresh;
	r_cons_break_push (NULL, NULL);

	while (!exit_graph && !is_error && !r_cons_is_breaked ()) {
		w = r_cons_get_size (&h);
		invscroll = r_config_get_i (core->config, "graph.invscroll");
		ret = agraph_refresh (grd);
		if (!ret) {
			is_error = true;
			break;
		}
		r_cons_show_cursor (false);
		wheel = r_config_get_i (core->config, "scr.wheel");
		if (wheel) {
			r_cons_enable_mouse (true);
		}

		// r_core_graph_inputhandle()
		okey = r_cons_readchar ();
		key = r_cons_arrow_to_hjkl (okey);

		if (core->cons->mouse_event) {
			movspeed = r_config_get_i (core->config, "scr.wheelspeed");
			switch (key) {
			case 'j':
			case 'k':
				switch (mousemode) {
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
			agraph_update_seek (g, get_anode (g->curnode), true);
			break;
		case '+':
			agraph_set_zoom (g, g->zoom + ZOOM_STEP);
			agraph_update_seek (g, get_anode (g->curnode), true);
			break;
		case '0':
			agraph_set_zoom (g, ZOOM_DEFAULT);
			agraph_update_seek (g, get_anode (g->curnode), true);
			break;
		case '|':
		{         // TODO: edit
			const char *buf = NULL;
			const char *cmd = r_config_get (core->config, "cmd.gprompt");
			r_line_set_prompt ("cmd.gprompt> ");
			core->cons->line->contents = strdup (cmd);
			buf = r_line_readline ();
			core->cons->line->contents = NULL;
			r_config_set (core->config, "cmd.gprompt", buf);
		}
		break;
#if 0
// disabled for now, ultraslow in most situations
		case '>':
			r_core_cmd0 (core, "ag-;.agc* $$;aggi");
			break;
		case '<':
			r_core_cmd0 (core, "ag-;.agc*;aggi");
			break;
#endif
		case 'G':
			r_core_cmd0 (core, "ag-;.dtg*;aggi");
			break;
		case 'V':
			if (fcn) {
				agraph_toggle_callgraph (g);
			}
			break;
		case 'Z':
			if (okey == 27) {
				agraph_prev_node (g);
			}
			break;
		case 's':
			key_s = r_config_get (core->config, "key.s");
			if (key_s && *key_s) {
				r_core_cmd0 (core, key_s);
			} else {
				graph_single_step_in (core, g);
			}
			break;
		case 'S':
			graph_single_step_over (core, g);
			break;
		case 'x':
		case 'X':
		{
			if (!fcn) {
				break;
			}
			ut64 old_off = core->offset;
			ut64 off = r_core_anal_get_bbaddr (core, core->offset);
			r_core_seek (core, off, 0);
			if ((key == 'x' && !r_core_visual_refs (core, true)) ||
			    (key == 'X' && !r_core_visual_refs (core, false))) {
				r_core_seek (core, old_off, 0);
			}
			break;
		}
		case 9: // tab
			agraph_next_node (g);
			break;
		case '?':
			r_cons_clear00 ();
			r_cons_printf ("Visual Ascii Art graph keybindings:\n"
				" :e cmd.gprompt = agft   - show tinygraph in one side\n"
				" +/-/0        - zoom in/out/default\n"
				" ;            - add comment in current basic block\n"
				" .            - center graph to the current node\n"
				" :cmd         - run radare command\n"
				" '            - toggle graph.comments\n"
				" \"            - toggle graph.refs\n"
				" /            - highlight text\n"
				" |            - set cmd.gprompt\n"
				" _            - enter hud selector\n"
				" >            - show function callgraph (see graph.refs)\n"
				" <            - show program callgraph (see graph.refs)\n"
				" Home/End     - go to the top/bottom of the canvas\n"
				" Page-UP/DOWN - scroll canvas up/down\n"
				" C            - toggle scr.colors\n"
				" d            - rename function\n"
				" F            - enter flag selector\n"
				" g([A-Za-z]*) - follow jmp/call identified by shortcut (like ;[ga])\n"
				" G            - debug trace callgraph (generated with dtc)\n"
				" hjkl         - scroll canvas\n"
				" HJKL         - move node\n"
				" m/M          - change mouse modes\n"
				" n/N          - next/previous scr.nkey (function/flag..)\n"
				" o            - go/seek to given offset\n"
				" p/P          - rotate graph modes (normal, display offsets, minigraph, summary)\n"
				" q            - back to Visual mode\n"
				" r            - refresh graph\n"
				" R            - randomize colors\n"
				" s/S          - step / step over\n"
				" tab          - select next node\n"
				" TAB          - select previous node\n"
				" t/f          - follow true/false edges\n"
				" u/U          - undo/redo seek\n"
				" V            - toggle basicblock / call graphs\n"
				" w            - toggle between movements speed 1 and graph.scroll\n"
				" x/X          - jump to xref/ref\n"
				" y            - toggle node folding/minification\n"
				" Y            - toggle tiny graph\n"
				" Z            - follow parent node");
			r_cons_flush ();
			r_cons_any_key (NULL);
			break;
		case '"':
			r_config_toggle (core->config, "graph.refs");
			break;
		case 'p':
			if (!fcn) {
				break;
			}
			g->mode = next_mode (g->mode);
			g->need_reload_nodes = true;
			break;
		case 'P':
			if (!fcn) {
				break;
			}
			g->mode = prev_mode (g->mode);
			g->need_reload_nodes = true;
			break;
		case 'g':
			goto_asmqjmps (g, core);
			break;
		case 'o':
			visual_offset (g, core);
			break;
		case 'u':
		{
			if (!fcn) {
				break;
			}
			RIOUndos *undo = r_io_sundo (core->io, core->offset);
			if (undo) {
				r_core_seek (core, undo->off, 0);
			} else {
				eprintf ("Cannot undo\n");
			}
			break;
		}
		case 'U':
		{
			if (!fcn) {
				break;
			}
			RIOUndos *undo = r_io_sundo_redo (core->io);
			if (undo) {
				r_core_seek (core, undo->off, 0);
			} else {
				eprintf ("Cannot redo\n");
			}
			break;
		}
		case 'r':
			if (fcn) {
				g->layout = r_config_get_i (core->config, "graph.layout");
				g->need_reload_nodes = true;
			}
			break;
		case '$':
			r_core_cmd0 (core, "e!asm.pseudo");
			g->need_reload_nodes = true;
			break;
		case 'R':
			if (!fcn) {
				break;
			}
			if (r_config_get_i (core->config, "scr.randpal")) {
				r_core_cmd0 (core, "ecr");
			} else {
				r_core_cmd0 (core, "ecn");
			}
			g->color_box = core->cons->pal.graph_box;
			g->color_box2 = core->cons->pal.graph_box2;
			g->color_box3 = core->cons->pal.graph_box3;
			g->color_true = core->cons->pal.graph_true;
			g->color_false = core->cons->pal.graph_false;
			get_bbupdate (g, core, fcn);
			break;
		case '!':
			r_core_visual_panels (core);
			break;
		case '\'':
			if (fcn) {
				r_config_toggle (core->config, "graph.comments");
				g->need_reload_nodes = true;
			}
			break;
		case ';':
			if (fcn) {
				char buf[256];
				r_line_set_prompt ("[comment]> ");
				if (r_cons_fgets (buf, sizeof (buf) - 1, 0, NULL) > 0) {
					r_core_cmdf (core, "\"CC %s\"", buf);
				}
				g->need_reload_nodes = true;
			}
			break;
		case 'C':
			r_config_toggle (core->config, "scr.color");
			break;
		case 'm':
			mousemode++;
			if (!mousemodes[mousemode]) {
				mousemode = 0;
			}
			break;
		case 'M':
			mousemode--;
			if (mousemode < 0) {
				mousemode = 3;
			}
			break;
		case 'd':
		{
			char *newname = r_cons_input ("New function name:");
			if (newname) {
				if (*newname) {
					r_core_cmdf (core, "\"afn %s\"", newname);
					get_bbupdate (g, core, fcn);
				}
				free (newname);
			}
		}
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
		case 'y':
			agraph_toggle_mini (g);
			break;
		case 'J':
			if (okey == 27) { // && r_cons_readchar () == 126) {
				// handle page down key
				can->sy -= PAGEKEY_SPEED * (invscroll? -1: 1);
			} else {
				RANode *n = get_anode (g->curnode);
				if (n) {
					if (g->is_tiny) {
						n->y++;
					} else {
						n->y += movspeed;
					}
				}
			}
			break;
		case 'K':
			if (okey == 27) { // && r_cons_readchar () == 126) {
				// handle page up key
				can->sy += PAGEKEY_SPEED * (invscroll? -1: 1);
			} else {
				RANode *n = get_anode (g->curnode);
				if (n) {
					if (g->is_tiny) {
						n->y --;
					} else {
						n->y -= movspeed;
					}
				}
			}
			break;
		case 'H':
			if (okey == 27) {
				// handle home key
				const RGraphNode *gn = find_near_of (g, NULL, true);
				g->update_seek_on = get_anode (gn);
			} else {
				RANode *n = get_anode (g->curnode);
				if (n) {
					if (g->is_tiny) {
						n->x --;
					} else {
						n->x -= movspeed;
					}
				}
			}
			break;
		case 'v':
			r_core_visual_anal (core);
			break;
		case 'L':
		{
			RANode *n = get_anode (g->curnode);
			if (n) {
				if (g->is_tiny) {
					n->x++;
				} else {
					n->x += movspeed;
				}
			}
			break;
		}
		case 'j': can->sy -= movspeed * (invscroll? -1: 1); break;
		case 'k': can->sy += movspeed * (invscroll? -1: 1); break;
		case 'l': can->sx -= movspeed * (invscroll? -1: 1); break;
		case 'h': can->sx += movspeed * (invscroll? -1: 1); break;
		case '.':
			agraph_update_seek (g, get_anode (g->curnode), true);
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
			r_config_set_i (core->config, "scr.interactive", true);
			r_core_cmd0 (core, "?i highlight;e scr.highlight=`?y`");
			r_config_set_i (core->config, "scr.interactive", false);
			break;
		case ':':
			r_core_visual_prompt_input (core);
			get_bbupdate (g, core, fcn);
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
			}
			break;
		case R_CONS_KEY_F2:
			cmd = r_config_get (core->config, "key.f2");
			if (cmd && *cmd) {
				(void) r_core_cmd0 (core, cmd);
			} else {
				graph_breakpoint (core);
			}
			break;
		case R_CONS_KEY_F3:
			cmd = r_config_get (core->config, "key.f3");
			if (cmd && *cmd) {
				(void) r_core_cmd0 (core, cmd);
			}
			break;
		case R_CONS_KEY_F4:
			cmd = r_config_get (core->config, "key.f4");
			if (cmd && *cmd) {
				(void) r_core_cmd0 (core, cmd);
			}
			break;
		case R_CONS_KEY_F5:
			cmd = r_config_get (core->config, "key.f5");
			if (cmd && *cmd) {
				(void)r_core_cmd0 (core, cmd);
			}
			break;
		case R_CONS_KEY_F6:
			cmd = r_config_get (core->config, "key.f6");
			if (cmd && *cmd) {
				(void)r_core_cmd0 (core, cmd);
			}
			break;
		case R_CONS_KEY_F7:
			cmd = r_config_get (core->config, "key.f7");
			if (cmd && *cmd) {
				key = r_core_cmd0 (core, cmd);
			} else {
				graph_single_step_in (core, g);
			}
			break;
		case R_CONS_KEY_F8:
			cmd = r_config_get (core->config, "key.f8");
			if (cmd && *cmd) {
				key = r_core_cmd0 (core, cmd);
			} else {
				graph_single_step_over (core, g);
			}
			break;
		case R_CONS_KEY_F9:
			cmd = r_config_get (core->config, "key.f9");
			if (cmd && *cmd) {
				key = r_core_cmd0 (core, cmd);
			} else {
				graph_continue (core);
			}
			break;
		case R_CONS_KEY_F10:
			cmd = r_config_get (core->config, "key.f10");
			if (cmd && *cmd) {
				(void)r_core_cmd0 (core, cmd);
			}
			break;
		case R_CONS_KEY_F11:
			cmd = r_config_get (core->config, "key.f11");
			if (cmd && *cmd) {
				(void)r_core_cmd0 (core, cmd);
			}
			break;
		case R_CONS_KEY_F12:
			cmd = r_config_get (core->config, "key.f12");
			if (cmd && *cmd) {
				(void)r_core_cmd0 (core, cmd);
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
	r_cons_break_pop ();
	r_config_set (core->config, "asm.comments", r_str_bool (asm_comments));
	core->cons->event_data = NULL;
	core->cons->event_resize = NULL;
	core->vmode = o_vmode;
	core->is_asmqjmps_letter = o_asmqjmps_letter;
	core->keep_asmqjmps = false;

	free (grd);
	if (graph_allocated) {
		r_agraph_free (g);
		r_config_set_i (core->config, "scr.interactive", o_scrinteractive);
	} else {
		g->can = o_can;
	}
	r_config_restore (hc);
	r_config_hold_free (hc);
	return !is_error;
}
