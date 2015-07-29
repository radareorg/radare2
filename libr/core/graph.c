/* Copyright radare2 2014-2015 - Author: pancake, ret2libc */

#include <r_core.h>
#include <r_cons.h>
#include <limits.h>

static const char *mousemodes[] = { "canvas-y", "canvas-x", "node-y", "node-x", NULL };
static int mousemode = 0;

#define BORDER 3
#define BORDER_WIDTH 4
#define BORDER_HEIGHT 3
#define MARGIN_TEXT_X 2
#define MARGIN_TEXT_Y 2
#define HORIZONTAL_NODE_SPACING 6
#define VERTICAL_NODE_SPACING 4
#define MIN_NODE_WIDTH 18
#define MIN_NODE_HEIGTH BORDER_HEIGHT
#define INIT_HISTORY_CAPACITY 16
#define TITLE_LEN 128
#define DEFAULT_SPEED 1
#define SMALLNODE_TEXT "[____]"
#define SMALLNODE_TEXT_CUR "[_@@_]"

#define ZOOM_STEP 10
#define ZOOM_DEFAULT 100

#define history_push(stack, x) (r_stack_push (stack, (void *)(size_t)x))
#define history_pop(stack) ((RGraphNode *)r_stack_pop (stack))

#define hash_set(sdb,k,v) (sdb_num_set (sdb, sdb_fmt (0, "%"PFMT64u, (ut64)(size_t)k), (ut64)(size_t)v, 0))
#define hash_get(sdb,k) (sdb_num_get (sdb, sdb_fmt (0, "%"PFMT64u, (ut64)(size_t)k), NULL))
#define hash_get_rnode(sdb,k) ((RGraphNode *)(size_t)hash_get (sdb, k))
#define hash_get_rlist(sdb,k) ((RList *)(size_t)hash_get (sdb, k))
#define hash_get_int(sdb,k) ((int)hash_get (sdb, k))

#define get_anode(gn) ((RANode *)gn->data)

#define graph_foreach_anode(list, it, pos, anode) \
	if (list) for (it = list->head; it && (pos = it->data) && (pos) && (anode = (RANode *)pos->data); it = it->n)

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
	RAEdgeCallback cb;
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
};

struct agraph_refresh_data {
	RCore *core;
	RAGraph *g;
	RAnalFunction **fcn;
	int fs;
};

#define G(x,y) r_cons_canvas_gotoxy (g->can, x, y)
#define W(x) r_cons_canvas_write (g->can, x)
#define B(x,y,w,h) r_cons_canvas_box(g->can, x,y,w,h, g->color_box)
#define B1(x,y,w,h) r_cons_canvas_box(g->can, x,y,w,h, g->color_box2)
#define B2(x,y,w,h) r_cons_canvas_box(g->can, x,y,w,h, g->color_box3)
#define F(x,y,x2,y2,c) r_cons_canvas_fill(g->can, x,y,x2,y2,c,0)

static char *get_title (ut64 addr) {
	return r_str_newf ("0x%"PFMT64x, addr);
}

static void update_node_dimension(const RGraph *g, int is_small, int zoom) {
	const RList *nodes = r_graph_get_nodes (g);
	RGraphNode *gn;
	RListIter *it;
	RANode *n;

	graph_foreach_anode (nodes, it, gn, n) {
		if (is_small) {
			n->h = 0;
			n->w = strlen (SMALLNODE_TEXT);
		} else {
			unsigned int len;

			n->w = r_str_bounds (n->body, (int *)&n->h);
			len = strlen (n->title) + MARGIN_TEXT_X;
			if (len > INT_MAX) len = INT_MAX;
			n->w = R_MAX (n->w, (int)len);
			n->w += BORDER_WIDTH;
			n->h += BORDER_HEIGHT;
			/* scale node by zoom */
			n->w = R_MAX (MIN_NODE_WIDTH, (n->w * zoom) / 100);
			n->h = R_MAX (MIN_NODE_HEIGTH, (n->h * zoom) / 100);
		}
	}
}

static void small_RANode_print(const RAGraph *g, const RANode *n, int cur) {
	char title[TITLE_LEN];

	if (!G (n->x + 2, n->y - 1))
		return;
	if (cur) {
		W(SMALLNODE_TEXT_CUR);
		(void)G (-g->can->sx, -g->can->sy + 2);
		snprintf (title, sizeof (title) - 1,
				"%s:", n->title);
		W (title);
		(void)G (-g->can->sx, -g->can->sy + 3);
		W (n->body);
	} else {
		W(SMALLNODE_TEXT);
	}
	return;
}

static void normal_RANode_print(const RAGraph *g, const RANode *n, int cur) {
	unsigned int center_x = 0, center_y = 0;
	unsigned int delta_x = 0, delta_txt_x = 0;
	unsigned int delta_y = 0, delta_txt_y = 0;
	char title[TITLE_LEN];
	char *body;
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
	if (x + MARGIN_TEXT_X < 0)
		delta_x = -(x + MARGIN_TEXT_X);
	if (x + n->w < -MARGIN_TEXT_X)
		return;
	if (y < -1)
		delta_y = R_MIN (n->h - BORDER_HEIGHT - 1, -y - MARGIN_TEXT_Y);

	/* print the title */
	if (cur) {
		snprintf (title, sizeof (title)-1,
				"[%s]", n->title);
	} else {
		snprintf (title, sizeof (title)-1,
				" %s ", n->title);
	}
	if (delta_x < strlen(title) && G(n->x + MARGIN_TEXT_X + delta_x, n->y + 1))
		W(title + delta_x);

	/* print the body */
	if (g->zoom > ZOOM_DEFAULT) {
		center_x = (g->zoom - ZOOM_DEFAULT) / 20;
		center_y = (g->zoom - ZOOM_DEFAULT) / 30;
		delta_txt_x = R_MIN (delta_x, center_x);
		delta_txt_y = R_MIN (delta_y, center_y);
	}

	if (G(n->x + MARGIN_TEXT_X + delta_x + center_x - delta_txt_x,
			n->y + MARGIN_TEXT_Y + delta_y + center_y - delta_txt_y)) {
		unsigned int body_x = center_x >= delta_x ? 0 : delta_x - center_x;
		unsigned int body_y = center_y >= delta_y ? 0 : delta_y - center_y;
		unsigned int body_h = BORDER_HEIGHT >= n->h ? 1 : n->h - BORDER_HEIGHT;

		if (g->zoom < ZOOM_DEFAULT) body_h--;
		if (body_y + 1 <= body_h) {
			body = r_str_ansi_crop (n->body,
					body_x, body_y,
					n->w - BORDER_WIDTH,
					body_h);
			if (body) {
				W (body);
				if (g->zoom < ZOOM_DEFAULT) W ("\n");
				free (body);
			} else {
				W (n->body);
			}
		}
		/* print some dots when the body is cropped because of zoom */
		if (body_y <= body_h && g->zoom < ZOOM_DEFAULT) {
			char *dots = "...";
			if (delta_x < strlen(dots)) {
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

static int **get_crossing_matrix (const RGraph *g,
		const struct layer_t layers[],
		int maxlayer, int i, int from_up,
		int *n_rows) {
	int len = layers[i].n_nodes;
	int **m;
	int j;

	m = R_NEWS0 (int *, len);
	if (!m)
		return NULL;

	for (j = 0; j < len; ++j) {
		m[j] = R_NEWS0 (int, len);
		if (!m[j])
			goto err_row;
	}

	/* calculate crossings between layer i and layer i-1 */
	/* consider the crossings generated by each pair of edges */
	if (i > 0 && from_up) {
		for (j = 0; j < layers[i - 1].n_nodes; ++j) {
			const RGraphNode *gj = layers[i - 1].nodes[j];
			const RList *neigh = r_graph_get_neighbours (g, gj);
			RGraphNode *gk;
			RListIter *itk;

			r_list_foreach (neigh, itk, gk) {
				int s;
				for (s = 0; s < j; ++s) {
					const RGraphNode *gs = layers[i - 1].nodes[s];
					const RList *neigh_s = r_graph_get_neighbours (g, gs);
					RGraphNode *gt;
					RListIter *itt;

					r_list_foreach (neigh_s, itt, gt) {
						const RANode *ak, *at; /* k and t should be "indexes" on layer i */

						if (gt == gk) continue;
						ak = get_anode (gk);
						at = get_anode (gt);
						if (ak->layer != i || at->layer != i) {
							 eprintf("\"%s\" (%d) or \"%s\" (%d) are not on the right layer (%d)\n",
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

					if (gs == gj) continue;
					neigh_s = r_graph_get_neighbours (g, gs);
					graph_foreach_anode (neigh_s, itt, gt, at) {
						if (at->pos_in_layer < ak->pos_in_layer)
							m[aj->pos_in_layer][as->pos_in_layer]++;
					}
				}
			}
		}
	}

	if (n_rows)
		*n_rows = len;
	return m;

err_row:
	for (i = 0; i < len; ++i) {
		if (m[i])
			free (m[i]);
	}
	free (m);
	return NULL;
}

static int layer_sweep (const RGraph *g, const struct layer_t layers[],
						int maxlayer, int i, int from_up) {
	int **cross_matrix;
	RGraphNode *u, *v;
	const RANode *au, *av;
	int n_rows, j, changed = R_FALSE;
	int len = layers[i].n_nodes;

	cross_matrix = get_crossing_matrix (g, layers, maxlayer, i, from_up, &n_rows);
	if (!cross_matrix) return R_FALSE;

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
			changed = R_TRUE;
		}
	}

	/* update position in the layer of each node. During the swap of some
	 * elements we didn't swap also the pos_in_layer because the cross_matrix
	 * is indexed by it, so do it now! */
	for (j = 0; j < layers[i].n_nodes; ++j) {
		RANode *n = get_anode (layers[i].nodes[j]);
		n->pos_in_layer = j;
	}

	for (j = 0; j < n_rows; ++j)
		free (cross_matrix[j]);
	free (cross_matrix);
	return changed;
}

static void view_cyclic_edge (const RGraphEdge *e, const RGraphVisitor *vis) {
	const RAGraph *g = (RAGraph *)vis->data;
	RGraphEdge *new_e = R_NEW (RGraphEdge);

	new_e->from = e->from;
	new_e->to = e->to;
	new_e->nth = e->nth;
	r_list_append (g->back_edges, new_e);
}

static int get_depth (Sdb *path, const RGraphNode *n) {
	int res = 0;
	while ((n = hash_get_rnode (path, n)) != NULL) {
		res++;
	}
	return res;
}

static void set_layer (const RGraphEdge *e, const RGraphVisitor *vis) {
	Sdb *path = (Sdb *)vis->data;
	int bdepth, adepth;

	adepth = get_depth (path, e->from);
	bdepth = get_depth (path, e->to);

	if (adepth + 1 > bdepth)
		hash_set (path, e->to, e->from);
}

static void view_dummy (const RGraphEdge *e, const RGraphVisitor *vis) {
	const RANode *a = get_anode (e->from);
	const RANode *b = get_anode (e->to);
	RList *long_edges = (RList *)vis->data;

	if (R_ABS (a->layer - b->layer) > 1) {
		RGraphEdge *new_e = R_NEW (RGraphEdge);
		new_e->from = e->from;
		new_e->to = e->to;
		new_e->nth = e->nth;
		r_list_append (long_edges, new_e);
	}
}

/* find a set of edges that, removed, makes the graph acyclic */
/* invert the edges identified in the previous step */
static void remove_cycles (RAGraph *g) {
	RGraphVisitor cyclic_vis = { NULL, NULL, NULL, NULL, NULL, NULL };
	const RGraphEdge *e;
	const RListIter *it;

	g->back_edges = r_list_new();
	cyclic_vis.back_edge = (RGraphEdgeCallback)view_cyclic_edge;
	cyclic_vis.data = g;
	r_graph_dfs (g->graph, &cyclic_vis);

	r_list_foreach (g->back_edges, it, e) {
		RANode *from, *to;
		from = e->from ? get_anode (e->from) : NULL;
		to = e->to ? get_anode (e->to) : NULL;
		r_agraph_del_edge (g, from, to);
		r_agraph_add_edge_at (g, to, from, e->nth);
	}
}

/* assign a layer to each node of the graph */
static void assign_layers (const RAGraph *g) {
	RGraphVisitor layer_vis = { NULL, NULL, NULL, NULL, NULL, NULL };
	Sdb *path_layers = sdb_new0 ();
	const RGraphNode *gn;
	const RListIter *it;
	RANode *n;

	layer_vis.data = path_layers;
	layer_vis.tree_edge = (RGraphEdgeCallback)set_layer;
	layer_vis.fcross_edge = (RGraphEdgeCallback)set_layer;
	r_graph_dfs (g->graph, &layer_vis);

	graph_foreach_anode (r_graph_get_nodes (g->graph), it, gn, n) {
		n->layer = get_depth (path_layers, gn);
	}

	sdb_free (path_layers);
}

static int find_edge (const RGraphEdge *a, const RGraphEdge *b) {
	return a->from == b->to && a->to == b->from ? 0 : 1;
}

static int is_reversed (const RAGraph *g, const RGraphEdge *e) {
	return r_list_find (g->back_edges, e, (RListComparator)find_edge) ? R_TRUE : R_FALSE;
}

/* add dummy nodes when there are edges that span multiple layers */
static void create_dummy_nodes (RAGraph *g) {
	RGraphVisitor dummy_vis = { NULL, NULL, NULL, NULL, NULL, NULL };
	const RListIter *it;
	const RGraphEdge *e;

	g->long_edges = r_list_new ();
	dummy_vis.data = g->long_edges;
	dummy_vis.tree_edge = (RGraphEdgeCallback)view_dummy;
	dummy_vis.fcross_edge = (RGraphEdgeCallback)view_dummy;
	r_graph_dfs (g->graph, &dummy_vis);

	r_list_foreach (g->long_edges, it, e) {
		RANode *from = get_anode (e->from);
		RANode *to = get_anode (e->to);
		int diff_layer = R_ABS (from->layer - to->layer);
		RANode *prev = get_anode(e->from);
		int i, nth = e->nth;

		r_agraph_del_edge (g, from, to);
		for (i = 1; i < diff_layer; ++i) {
			RANode *dummy = r_agraph_add_node (g, NULL, NULL);
			if (!dummy) return;
			dummy->is_dummy = R_TRUE;
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
static void create_layers (RAGraph *g) {
	const RList *nodes = r_graph_get_nodes (g->graph);
	RGraphNode *gn;
	const RListIter *it;
	RANode *n;
	int i;

	/* identify max layer */
	g->n_layers = 0;
	graph_foreach_anode (nodes, it, gn, n) {
		if (n->layer > g->n_layers)
			g->n_layers = n->layer;
	}

	/* create a starting ordering of nodes for each layer */
	g->n_layers++;
	g->layers = R_NEWS0 (struct layer_t, g->n_layers);

	graph_foreach_anode (nodes, it, gn, n)
		g->layers[n->layer].n_nodes++;

	for (i = 0; i < g->n_layers; ++i) {
		g->layers[i].nodes = R_NEWS (RGraphNode *, g->layers[i].n_nodes);
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
static void minimize_crossings (const RAGraph *g) {
	int i, cross_changed;

	do {
		cross_changed = R_FALSE;

		for (i = 0; i < g->n_layers; ++i)
			cross_changed |= layer_sweep (g->graph, g->layers, g->n_layers, i, R_TRUE);
	} while (cross_changed);

	do {
		cross_changed = R_FALSE;

		for (i = g->n_layers - 1; i >= 0; --i)
			cross_changed |= layer_sweep (g->graph, g->layers, g->n_layers, i, R_FALSE);
	} while (cross_changed);
}

static int find_dist (const struct dist_t *a, const struct dist_t *b) {
	return a->from == b->from && a->to == b->to ? 0 : 1;
}

/* returns the distance between two nodes */
/* if the distance between two nodes were explicitly set, returns that;
 * otherwise calculate the distance of two nodes on the same layer */
static int dist_nodes (const RAGraph *g, const RGraphNode *a, const RGraphNode *b) {
	struct dist_t d;
	const RANode *aa, *ab;
	RListIter *it;
	int res = 0;

	if (g->dists) {
		d.from = a;
		d.to = b;
		it = r_list_find (g->dists, &d, (RListComparator)find_dist);
		if (it) {
			struct dist_t *old = (struct dist_t *)r_list_iter_get_data (it);
			return old->dist;
		}
	}

	aa = get_anode (a);
	ab = get_anode (b);
	if (aa->layer == ab->layer) {
		int i;

		res = aa == ab && !aa->is_reversed ? HORIZONTAL_NODE_SPACING : 0;
		for (i = aa->pos_in_layer; i < ab->pos_in_layer; ++i) {
			const RGraphNode *cur = g->layers[aa->layer].nodes[i];
			const RGraphNode *next = g->layers[aa->layer].nodes[i + 1];
			const RANode *anext = get_anode (next);
			const RANode *acur = get_anode (cur);
			int found = R_FALSE;

			if (g->dists) {
				d.from = cur;
				d.to = next;
				it = r_list_find (g->dists, &d, (RListComparator)find_dist);
				if (it) {
					struct dist_t *old = (struct dist_t *)r_list_iter_get_data (it);
					res += old->dist;
					found = R_TRUE;
				}
			}

			if (!found) {
				int space = HORIZONTAL_NODE_SPACING;
				if (acur->is_reversed && anext->is_reversed) {
					if (!acur->is_reversed)
						res += acur->w / 2;
					else if (!anext->is_reversed)
						res += anext->w / 2;
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
static void set_dist_nodes (const RAGraph *g, int l, int cur, int next) {
	struct dist_t *d, find_el;
	const RGraphNode *vi, *vip;
	const RANode *avi, *avip;
	RListIter *it;

	if (!g->dists) return;
	vi = g->layers[l].nodes[cur];
	vip = g->layers[l].nodes[next];
	avi = get_anode (vi);
	avip = get_anode (vip);

	find_el.from = vi;
	find_el.to = vip;
	it = r_list_find (g->dists, &find_el, (RListComparator)find_dist);
	d = it ? (struct dist_t *)r_list_iter_get_data (it) : R_NEW (struct dist_t);

	d->from = vi;
	d->to = vip;
	d->dist = avip->x - avi->x;
	if (!it)
		r_list_push (g->dists, d);
}

static int is_valid_pos (const RAGraph *g, int l, int pos) {
	return pos >= 0 && pos < g->layers[l].n_nodes;
}

/* computes the set of vertical classes in the graph */
/* if v is an original node, L(v) = { v }
 * if v is a dummy node, L(v) is the set of all the dummies node that belongs
 *      to the same long edge */
static Sdb *compute_vertical_nodes (const RAGraph *g) {
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
						if (!next) break;
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
static RList **compute_classes (const RAGraph *g, Sdb *v_nodes, int is_left, int *n_classes) {
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

		for (j = is_left ? 0 : g->layers[i].n_nodes - 1;
			(is_left && j < g->layers[i].n_nodes) || (!is_left && j >= 0);
			j = is_left ? j + 1 : j - 1) {
			const RGraphNode *gj = g->layers[i].nodes[j];
			const RANode *aj = get_anode (gj);

			if (aj->klass == -1) {
				const RList *laj = hash_get_rlist (v_nodes, gj);

				if (!res[c])
					res[c] = r_list_new ();
				graph_foreach_anode (laj, it, gn, n) {
					r_list_append (res[c], gn);
					n->klass = c;
				}
			} else {
				c = aj->klass;
			}
		}
	}

	if (n_classes)
		*n_classes = g->n_layers;
	return res;
}

static int cmp_dist (const size_t a, const size_t b) {
	return (int)a < (int)b;
}

static RGraphNode *get_sibling (const RAGraph *g, const RANode *n, int is_left, int is_adjust_class) {
	RGraphNode *res = NULL;
	int pos = n->pos_in_layer;

	if ((is_left && is_adjust_class) || (!is_left && !is_adjust_class))
		pos++;
	else pos--;

	if (is_valid_pos (g, n->layer, pos))
		res = g->layers[n->layer].nodes[pos];
	return res;
}

static int adjust_class_val (const RAGraph *g, const RGraphNode *gn,
							 const RGraphNode *sibl, Sdb *res, int is_left) {
	if (is_left)
		return hash_get_int (res, sibl) - hash_get_int (res, gn) - dist_nodes (g, gn, sibl);
	else
		return hash_get_int (res, gn) - hash_get_int (res, sibl) - dist_nodes (g, sibl, gn);
}

/* adjusts the position of previously placed left/right classes */
/* tries to place classes as close as possible */
static void adjust_class (const RAGraph *g, int is_left,
						  RList **classes, Sdb *res, int c) {
	const RGraphNode *gn;
	const RListIter *it;
	const RANode *an;
	int dist, v, is_first = R_TRUE;

	graph_foreach_anode (classes[c], it, gn, an) {
		const RGraphNode *sibling;
		const RANode *sibl_anode;

		sibling = get_sibling (g, an, is_left, R_TRUE);
		if (!sibling) continue;
		sibl_anode = get_anode (sibling);
		if (sibl_anode->klass == c) continue;
		v = adjust_class_val (g, gn, sibling, res, is_left);
		dist = is_first ? v : R_MIN (dist, v);
		is_first = R_FALSE;
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
				if (ak->klass < c)
					r_list_append (heap, (void *)(size_t)(ak->x - an->x));
			}
		}

		len = r_list_length (heap);
		if (len == 0) {
			dist = 0;
		} else {
			r_list_sort (heap, (RListComparator)cmp_dist);
			dist = (int)(size_t)r_list_get_n (heap, len / 2);
		}

		r_list_free (heap);
	}

	graph_foreach_anode (classes[c], it, gn, an) {
		const int old_val = hash_get_int (res, gn);
		const int new_val = is_left ?  old_val + dist : old_val - dist;
		hash_set (res, gn, new_val);
	}
}

static int place_nodes_val (const RAGraph *g, const RGraphNode *gn,
		const RGraphNode *sibl, Sdb *res, int is_left) {
	if (is_left)
		return hash_get_int (res, sibl) + dist_nodes (g, sibl, gn);
	return hash_get_int (res, sibl) - dist_nodes (g, gn, sibl);
}

static int place_nodes_sel_p (int newval, int oldval, int is_first, int is_left) {
	if (is_first)
		return newval;

	if (is_left)
		return R_MAX (oldval, newval);
	else
		return R_MIN (oldval, newval);
}

/* places left/right the nodes of a class */
static void place_nodes (const RAGraph *g, const RGraphNode *gn, int is_left,
						 Sdb *v_nodes, RList **classes, Sdb *res, Sdb *placed) {
	const RList *lv = hash_get_rlist (v_nodes, gn);
	int p, v, is_first = R_TRUE;
	const RGraphNode *gk;
	const RListIter *itk;
	const RANode *ak;

	graph_foreach_anode (lv, itk, gk, ak) {
		const RGraphNode *sibling;
		const RANode *sibl_anode;

		sibling = get_sibling (g, ak, is_left, R_FALSE);
		if (!sibling) continue;
		sibl_anode = get_anode (sibling);
		if (ak->klass == sibl_anode->klass) {
			if (!hash_get (placed, sibling))
				place_nodes (g, sibling, is_left, v_nodes, classes, res, placed);

			v = place_nodes_val (g, gk, sibling, res, is_left);
			p = place_nodes_sel_p (v, p, is_first, is_left);
			is_first = R_FALSE;
		}
	}

	if (is_first)
		p = is_left ? 0 : 50;

	graph_foreach_anode (lv, itk, gk, ak) {
		hash_set (res, gk, p);
		hash_set (placed, gk, R_TRUE);
	}
}

/* computes the position to the left/right of all the nodes */
static Sdb *compute_pos (const RAGraph *g, int is_left, Sdb *v_nodes) {
	Sdb *res, *placed;
	RList **classes;
	int n_classes, i;

	classes = compute_classes (g, v_nodes, is_left, &n_classes);
	if (!classes) return NULL;

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
		if (classes[i])
			r_list_free (classes[i]);
	}
	free (classes);
	return res;
}

/* calculates position of all nodes, but in particular dummies nodes */
/* computes two different placements (called "left"/"right") and set the final
 * position of each node to the average of the values in the two placements */
static void place_dummies (const RAGraph *g) {
	const RList *nodes;
	Sdb *xminus, *xplus, *vertical_nodes;
	const RGraphNode *gn;
	const RListIter *it;
	RANode *n;

	vertical_nodes = compute_vertical_nodes (g);
	if (!vertical_nodes) return;
	xminus = compute_pos (g, R_TRUE, vertical_nodes);
	if (!xminus) goto xminus_err;
	xplus = compute_pos (g, R_FALSE, vertical_nodes);
	if (!xplus) goto xplus_err;

	nodes = r_graph_get_nodes (g->graph);
	graph_foreach_anode (nodes, it, gn, n) {
		n->x = (hash_get_int (xminus, gn) + hash_get_int (xplus, gn)) / 2;
	}

	sdb_free (xplus);
xplus_err:
	sdb_free (xminus);
xminus_err:
	sdb_free (vertical_nodes);
}

static RGraphNode *get_right_dummy (const RAGraph *g, const RGraphNode *n) {
	const RANode *an = get_anode (n);
	int k, layer = an->layer;

	for (k = an->pos_in_layer + 1; k < g->layers[layer].n_nodes; ++k) {
		RGraphNode *gk = g->layers[layer].nodes[k];
		const RANode *ak = get_anode (gk);

		if (ak->is_dummy)
			return gk;
	}

	return NULL;
}

static void adjust_directions (const RAGraph *g, int i, int from_up, Sdb *D, Sdb *P) {
	const RGraphNode *vm = NULL, *wm = NULL;
	const RANode *vma = NULL, *wma = NULL;
	int j, d = from_up ? 1 : -1;

	if (i + d < 0 || i + d >= g->n_layers) return;

	for (j = 0; j < g->layers[i + d].n_nodes; ++j) {
		const RGraphNode *wp, *vp = g->layers[i + d].nodes[j];
		const RANode *wpa, *vpa = get_anode (vp);

		if (!vpa->is_dummy) continue;
		if (from_up)
			wp = r_list_get_n (r_graph_innodes (g->graph, vp), 0);
		else
			wp = r_graph_nth_neighbour (g->graph, vp, 0);
		wpa = get_anode (wp);
		if (!wpa->is_dummy) continue;

		if (vm) {
			int p = hash_get_int (P, wm);
			int k;

			for (k = wma->pos_in_layer + 1; k < wpa->pos_in_layer; ++k) {
				const RGraphNode *w = g->layers[wma->layer].nodes[k];
				const RANode *aw = get_anode (w);

				if (aw->is_dummy)
					p &= hash_get_int (P, w);
			}
			if (p) {
				hash_set (D, vm, from_up);
				for (k = vma->pos_in_layer + 1; k < vpa->pos_in_layer; ++k) {
					const RGraphNode *v = g->layers[vma->layer].nodes[k];
					const RANode *av = get_anode (v);

					if (av->is_dummy)
						hash_set (D, v, from_up);
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
static void place_single (const RAGraph *g, int l, const RGraphNode *bm,
						  const RGraphNode *bp, int from_up, int va) {
	const RGraphNode *gk, *v = g->layers[l].nodes[va];
	const RANode *ak;
	RANode *av = get_anode (v);
	const RList *neigh;
	const RListIter *itk;
	int len;

	if (from_up)
		neigh = r_graph_innodes (g->graph, v);
	else
		neigh = r_graph_get_neighbours (g->graph, v);

	len = r_list_length (neigh);
	if (len == 0)
		return;

	int sum_x = 0;
	graph_foreach_anode (neigh, itk, gk, ak) {
		if (ak->is_reversed) {
			len--;
			continue;
		}

		sum_x += ak->x;
	}

	if (len == 0)
		return;

	av->x = sum_x / len;
	if (bm) {
		const RANode *bma = get_anode (bm);
		av->x = R_MAX (av->x, bma->x + dist_nodes (g, bm, v));
	}
	if (bp) {
		const RANode *bpa = get_anode (bp);
		av->x = R_MIN (av->x, bpa->x - dist_nodes (g, v, bp));
	}
}

static int RM_listcmp (const struct len_pos_t *a, const struct len_pos_t *b) {
	return a->pos < b->pos;
}

static int RP_listcmp (const struct len_pos_t *a, const struct len_pos_t *b) {
	return a->pos >= b->pos;
}

static void collect_changes (const RAGraph *g, int l, const RGraphNode *b,
							 int from_up, int s, int e, RList *list, int is_left) {
	const RGraphNode *vt = g->layers[l].nodes[e - 1];
	const RGraphNode *vtp = g->layers[l].nodes[s];
	RListComparator lcmp;
	struct len_pos_t *cx;
	int i;

	lcmp = is_left ? (RListComparator)RM_listcmp : (RListComparator)RP_listcmp;

	for (i = is_left ? s : e - 1;
	     (is_left && i < e) || (!is_left && i >= s);
		 i = is_left ? i + 1 : i - 1) {
		const RGraphNode *v, *vi = g->layers[l].nodes[i];
		const RANode *av, *avi = get_anode (vi);
		const RList *neigh;
		const RListIter *it;
		int c = 0;

		if (from_up)
			neigh = r_graph_innodes (g->graph, vi);
		else
			neigh = r_graph_get_neighbours (g->graph, vi);

		graph_foreach_anode (neigh, it, v, av) {
			if ((is_left && av->x >= avi->x) || (!is_left && av->x <= avi->x)) {
				c++;
			} else {
				cx = R_NEW (struct len_pos_t);

				c--;
				cx->len = 2;
				cx->pos = av->x;
				if (is_left)
					cx->pos += dist_nodes (g, vi, vt);
				else
					cx->pos -= dist_nodes (g, vtp, vi);
				r_list_add_sorted (list, cx, lcmp);
			}
		}

		cx = R_NEW (struct len_pos_t);
		cx->len = c;
		cx->pos = avi->x;
		if (is_left)
			cx->pos += dist_nodes (g, vi, vt);
		else
			cx->pos -= dist_nodes (g, vtp, vi);
		r_list_add_sorted (list, cx, lcmp);
	}

	if (b) {
		const RANode *ab = get_anode (b);

		cx = R_NEW (struct len_pos_t);
		cx->len = is_left ? INT_MAX : INT_MIN;
		cx->pos = ab->x;
		if (is_left)
			cx->pos += dist_nodes (g, b, vt);
		else
			cx->pos -= dist_nodes (g, vtp, b);
		r_list_add_sorted (list, cx, lcmp);
	}
}

static void combine_sequences (const RAGraph *g, int l,
							   const RGraphNode *bm, const RGraphNode *bp,
							   int from_up, int a, int r) {
	RList *Rm = r_list_new (), *Rp = r_list_new ();
	const RGraphNode *vt, *vtp;
	RANode *at, *atp;
	int rm, rp, t, m, i;

	t = (a + r) / 2;
	vt = g->layers[l].nodes[t - 1];
	vtp = g->layers[l].nodes[t];
	at = get_anode (vt);
	atp = get_anode (vtp);

	collect_changes (g, l, bm, from_up, a, t, Rm, R_TRUE);
	collect_changes (g, l, bp, from_up, t, r, Rp, R_FALSE);
	rm = rp = 0;

	m = dist_nodes (g, vt, vtp);
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
					struct len_pos_t *cx = (struct len_pos_t *)r_list_pop (Rm);
					rm = rm + cx->len;
					at->x = R_MAX (cx->pos, atp->x - m);
					free (cx);
				}
			} else {
				if (r_list_empty (Rp)) {
					atp->x = at->x + m;
				} else {
					struct len_pos_t *cx = (struct len_pos_t *)r_list_pop (Rp);
					rp = rp + cx->len;
					atp->x = R_MIN (cx->pos, at->x + m);
					free (cx);
				}
			}
		}
	}

	r_list_free (Rm);
	r_list_free (Rp);

	for (i = t - 2; i >= a; --i) {
		const RGraphNode *gv = g->layers[l].nodes[i];
		RANode *av = get_anode (gv);

		av->x = R_MIN (av->x, at->x - dist_nodes (g, gv, vt));
	}

	for (i = t + 1; i < r; ++i) {
		const RGraphNode *gv = g->layers[l].nodes[i];
		RANode *av = get_anode (gv);

		av->x = R_MAX (av->x, atp->x + dist_nodes (g, vtp, gv));
	}
}

/* places a sequence of consecutive original nodes */
/* it tries to minimize the distance between each node in the sequence and its
 * neighbours in the "previous" layer. Those neighbours are considered as
 * "fixed". The previous layer depends on the direction used during the layers
 * traversal */
static void place_sequence (const RAGraph *g, int l,
							const RGraphNode *bm, const RGraphNode *bp,
							int from_up, int va, int vr) {
	int vt;

	if (vr == va + 1) {
		place_single (g, l, bm, bp, from_up, va);
	} else if (vr > va + 1) {
		vt = (vr + va) / 2;
		place_sequence (g, l, bm, bp, from_up, va, vt);
		place_sequence (g, l, bm, bp, from_up, vt, vr);
		combine_sequences (g, l, bm, bp, from_up, va, vr);
	}
}

/* finds the placements of nodes while traversing the graph in the given
 * direction */
/* places all the sequences of consecutive original nodes in each layer. */
static void original_traverse_l (const RAGraph *g, Sdb *D, Sdb *P, int from_up) {
	int i, k, va, vr;

	for (i = from_up ? 0 : g->n_layers - 1;
		(from_up && i < g->n_layers) || (!from_up && i >= 0);
		i = from_up ? i + 1 : i - 1) {
		int j;
		const RGraphNode *bm = NULL;
		const RANode *bma = NULL;

		j = 0;
		while (j < g->layers[i].n_nodes && !bm) {
			const RGraphNode *gn = g->layers[i].nodes[j];
			const RANode *an = get_anode (gn);

			if (an->is_dummy) {
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
		for (k = va; k < vr - 1; ++k)
			set_dist_nodes (g, i, k, k + 1);

		if (is_valid_pos (g, i, vr - 1) && bm)
			set_dist_nodes (g, i, vr - 1, bma->pos_in_layer);

		while (bm) {
			const RGraphNode *bp = get_right_dummy (g, bm);
			const RANode *bpa = NULL;
			bma = get_anode (bm);

			if (!bp) {
				va = bma->pos_in_layer + 1;
				vr = g->layers[bma->layer].n_nodes;
				place_sequence (g, i, bm, NULL, from_up, va, vr);
				for (k = va; k < vr - 1; ++k)
					set_dist_nodes (g, i, k, k + 1);

				if (is_valid_pos (g, i, va))
					set_dist_nodes (g, i, bma->pos_in_layer, va);
			} else if (hash_get_int (D, bm) == from_up) {
				bpa = get_anode (bp);
				va = bma->pos_in_layer + 1;
				vr = bpa->pos_in_layer;
				place_sequence (g, i, bm, bp, from_up, va, vr);
				hash_set (P, bm, R_TRUE);
			}

			bm = bp;
		}

		adjust_directions (g, i, from_up, D, P);
	}
}

/* computes a final position of original nodes, considering dummies nodes as
 * fixed */
/* set the node placements traversing the graph downward and then upward */
static void place_original (RAGraph *g) {
	const RList *nodes = r_graph_get_nodes (g->graph);
	Sdb *D, *P;
	const RGraphNode *gn;
	const RListIter *itn;
	const RANode *an;

	D = sdb_new0 ();
	P = sdb_new0 ();
	g->dists = r_list_new ();
	g->dists->free = (RListFree)free;

	graph_foreach_anode (nodes, itn, gn, an) {
		if (!an->is_dummy) continue;
		const RGraphNode *right_v = get_right_dummy (g, gn);
		if (right_v) {
			const RANode *right = get_anode (right_v);

			hash_set (D, gn, 0);
			int dt_eq = right->x - an->x == dist_nodes (g, gn, right_v);
			hash_set (P, gn, dt_eq);
		}
	}

	original_traverse_l (g, D, P, R_TRUE);
	original_traverse_l (g, D, P, R_FALSE);

	r_list_free (g->dists);
	g->dists = NULL;
	sdb_free (P);
	sdb_free (D);
}

static void restore_original_edges (const RAGraph *g) {
	const RListIter *it;
	const RGraphEdge *e;

	r_list_foreach (g->long_edges, it, e) {
		RANode *from, *to;
		from = e->from ? get_anode (e->from) : NULL;
		to = e->to ? get_anode (e->to) : NULL;
		r_agraph_add_edge_at (g, from, to, e->nth);
	}

	r_list_foreach (g->back_edges, it, e) {
		RANode *from, *to;
		from = e->from ? get_anode (e->from) : NULL;
		to = e->to ? get_anode (e->to) : NULL;
		r_agraph_del_edge (g, to, from);
		r_agraph_add_edge_at (g, from, to, e->nth);
	}
}

static void remove_dummy_nodes (const RAGraph *g) {
	RGraphNode *gn;
	const RListIter *it;
	RList *toremove = r_list_new ();
	int i, j;

	/* traverse all dummy nodes to keep track
	 * of the path long edges should go by */
	for (i = 0; i < g->n_layers; ++i) {
		for (j = 0; j < g->layers[i].n_nodes; ++j) {
			RGraphNode *n = g->layers[i].nodes[j];
			RANode *an = get_anode (n);
			if (!an->is_dummy || r_list_contains (toremove, n)) continue;

			RGraphNode *from = r_list_get_n (r_graph_innodes (g->graph, n), 0);
			RANode *a_from = get_anode (from);
			RListIter *(*add_to_list)(RList *, void *) = NULL;
			AEdge *e = R_NEW0 (AEdge);

			e->x = r_list_new ();
			e->y = r_list_new ();
			e->is_reversed = an->is_reversed;
			if (e->is_reversed) {
				e->to = a_from;
				add_to_list = r_list_prepend;
				add_to_list (e->x, (void *)(size_t)an->x);
				add_to_list (e->y, (void *)(size_t)a_from->y);
			} else {
				e->from = a_from;
				add_to_list = r_list_append;
			}

			while (an->is_dummy) {
				add_to_list (toremove, n);

				add_to_list (e->x, (void *)(size_t)an->x);
				add_to_list (e->y, (void *)(size_t)an->y);

				add_to_list (e->x, (void *)(size_t)an->x);
				add_to_list (e->y, (void *)(size_t)
						(an->y + g->layers[an->layer].height));

				n = r_graph_nth_neighbour (g->graph, n, 0);
				an = get_anode (n);
			}

			if (e->is_reversed)
				e->from = an;
			else
				e->to = an;
			r_list_append (g->edges, e);
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

	if (g->edges) r_list_free (g->edges);
	g->edges = r_list_new ();

	remove_cycles (g);
	assign_layers (g);
	create_dummy_nodes (g);
	create_layers (g);
	minimize_crossings (g);

	/* identify row height */
	for (i = 0; i < g->n_layers; i++) {
		int rh = 0;
		for (j = 0; j < g->layers[i].n_nodes; ++j) {
			const RANode *n = get_anode (g->layers[i].nodes[j]);
			if (n->h > rh)
				rh = n->h;
		}
		g->layers[i].height = rh;
	}

	/* x-coordinate assignment: algorithm based on:
	 * A Fast Layout Algorithm for k-Level Graphs
	 * by C. Buchheim, M. Junger, S. Leipert */
	place_dummies (g);
	place_original (g);

	/* vertical align */
	for (i = 0; i < g->n_layers; ++i) {
		for (j = 0; j < g->layers[i].n_nodes; ++j) {
			RANode *n = get_anode (g->layers[i].nodes[j]);
			n->y = 1;
			for (k = 0; k < n->layer; ++k) {
				n->y += g->layers[k].height + VERTICAL_NODE_SPACING;
			}
		}
	}

	/* finalize x coordinate */
	for (i = 0; i < g->n_layers; ++i) {
		for (j = 0; j < g->layers[i].n_nodes; ++j) {
			RANode *n = get_anode (g->layers[i].nodes[j]);
			n->x -= n->w / 2;
		}
	}

	restore_original_edges (g);
	remove_dummy_nodes (g);

	/* free all temporary structures used during layout */
	for (i = 0; i < g->n_layers; ++i)
		free (g->layers[i].nodes);
	free (g->layers);
	r_list_free (g->long_edges);
	r_list_free (g->back_edges);
}

/* build the RGraph inside the RAGraph g, starting from the Basic Blocks */
static int get_bbnodes(RAGraph *g, RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *iter;

	r_list_foreach (fcn->bbs, iter, bb) {
		RANode *node;
		char *title, *body;

		if (bb->addr == UT64_MAX)
			continue;

		if (g->is_simple_mode) {
			body = r_core_cmd_strf (core,
					"pI %d @ 0x%08"PFMT64x, bb->size, bb->addr);
		}else {
			body = r_core_cmd_strf (core,
					"pDi %d @ 0x%08"PFMT64x, bb->size, bb->addr);
		}
		title = get_title (bb->addr);

		node = r_agraph_add_node (g, title, body);
		free (body);
		free (title);
		if (!node) {
			return R_FALSE;
		}
	}

	r_list_foreach (fcn->bbs, iter, bb) {
		RANode *u, *v;
		char *title;

		if (bb->addr == UT64_MAX)
			continue;

		title = get_title (bb->addr);
		u = r_agraph_get_node (g, title);
		if (title) free (title);
		if (bb->jump != UT64_MAX) {
			title = get_title (bb->jump);
			v = r_agraph_get_node (g, title);
			if (title) free (title);
			r_agraph_add_edge (g, u, v);
		}
		if (bb->fail != UT64_MAX) {
			title = get_title (bb->fail);
			v = r_agraph_get_node (g, title);
			if (title) free (title);
			r_agraph_add_edge (g, u, v);
		}
	}

	return R_TRUE;
}

/* build the RGraph inside the RAGraph g, starting from the Call Graph
 * information */
static int get_cgnodes(RAGraph *g, RCore *core, RAnalFunction *fcn) {
#if FCN_OLD
	RANode *node, *fcn_anode;
	RListIter *iter;
	RAnalRef *ref;
	char *code, *title, *body;

	title = get_title (fcn->addr);
	fcn_anode = r_agraph_add_node (g, title, "");

	free (title);
	if (!fcn_anode)
		return R_FALSE;

	fcn_anode->x = 10;
	fcn_anode->y = 3;

	r_list_foreach (fcn->refs, iter, ref) {
		/* XXX: something is broken, why there are duplicated
		 *      nodes here?! goto check fcn->refs!! */
		/* avoid dups wtf */
		title = get_title (ref->addr);
		if (r_agraph_get_node (g, title) != NULL)
				continue;
		if (title) free (title);

		RFlagItem *fi = r_flag_get_at (core->flags, ref->addr);

		if (fi) {
			body = strdup (fi->name);
			body = r_str_concat (body, ":\n");
		} else {
			body = strdup ("");
		}
		code = r_core_cmd_strf (core,
			"pi 4 @ 0x%08"PFMT64x, ref->addr);
		body = r_str_concat (body, code);
		body = r_str_concat (body, "...\n");
		title = get_title (ref->addr);

		node = r_agraph_add_node (g, title, body);
		if (!node)
			return R_FALSE;
		free (title);
		free (body);

		node->x = 10;
		node->y = 10;
		free (code);

		r_agraph_add_edge (g, fcn_anode, node);
	}

#else
	eprintf ("Must be sdbized\n");
#endif

	return R_TRUE;
}

static int reload_nodes(RAGraph *g, RCore *core, RAnalFunction *fcn) {
	int ret;
	int is_c = g->is_callgraph;

	ret = is_c ? get_cgnodes(g, core, fcn) : get_bbnodes(g, core, fcn);
	return ret;
}

static void update_seek(RConsCanvas *can, RANode *n, int force) {
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

static int is_near (const RANode *n, int x, int y, int is_next) {
	if (is_next)
		return (n->y == y && n->x > x) || n->y > y;
	else
		return (n->y == y && n->x < x) || n->y < y;
}

static const RGraphNode *find_near_of (const RAGraph *g, const RGraphNode *cur,
									   int is_next) {
	/* XXX: it's slow */
	const RList *nodes = r_graph_get_nodes (g->graph);
	const RListIter *it;
	const RGraphNode *gn, *resgn = NULL;
	const RANode *n, *acur = cur ? get_anode (cur) : NULL;
	int default_v = is_next ? INT_MIN : INT_MAX;
	int start_y = acur ? acur->y : default_v;
	int start_x = acur ? acur->x : default_v;

	graph_foreach_anode (nodes, it, gn, n) {
		if (is_near (n, start_x, start_y, is_next)) {
			const RANode *resn;

			if (!resgn) {
				resgn = gn;
				continue;
			}

			resn = get_anode (resgn);
			if ((is_next && resn->y > n->y) || (!is_next && resn->y < n->y))
				resgn = gn;
			else if ((is_next && resn->y == n->y && resn->x > n->x) ||
					(!is_next && resn->y == n->y && resn->x < n->x))
				resgn = gn;
		}
	}

	if (!resgn && cur)
		resgn = find_near_of (g, NULL, is_next);

	return resgn;
}

static void update_graph_sizes (RAGraph *g) {
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
		if (ak->x < g->x) g->x = ak->x;
		if (ak->y < g->y) {
			g->y = ak->y;
			min_gn = ak;
		}
		if (ak->x + ak->w > max_x) max_x = ak->x + ak->w;
		if (ak->y + ak->h > max_y) {
			max_y = ak->y + ak->h;
			max_gn = ak;
		}
	}

	/* while calculating the graph size, take into account long edges */
	r_list_foreach (g->edges, it, e) {
		RListIter *kt;
		void *vv;
		int v;

		r_list_foreach (e->x, kt, vv) {
			v = (int)(size_t)vv;
			if (v < g->x) g->x = v;
			if (v + 1 > max_x) max_x = v + 1;
		}
		r_list_foreach (e->y, kt, vv) {
			v = (int)(size_t)vv;
			if (v < g->y) g->y = v;
			if (v + 1 > max_y) max_y = v + 1;
		}
	}

	if (min_gn) {
		const RList *neigh = r_graph_innodes (g->graph, min_gn->gnode);
		if (r_list_length (neigh) > 0) {
			g->y--;
			max_y++;
		}
	}
	if (max_gn) {
		const RList *neigh = r_graph_get_neighbours (g->graph, min_gn->gnode);
		if (r_list_length (neigh) > 0)
			max_y++;
	}

	if (g->x != INT_MAX && g->y != INT_MAX) {
		g->w = max_x - g->x;
		if (g->title) {
			size_t len = strlen (g->title);
			if (len > INT_MAX) g->w = INT_MAX;
			if ((int)len > g->w) g->w = len;
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
	delta_x = g->x < 0 ? -g->x : 0;
	delta_y = g->y < 0 ? -g->y : 0;
	sdb_num_set (g->db, "agraph.delta_x", delta_x, 0);
	sdb_num_set (g->db, "agraph.delta_y", delta_y, 0);
}

static void set_curnode (RAGraph *g, const RGraphNode *n) {
	g->curnode = n;
	if (n) {
		RANode *a = get_anode (n);
		if (a->title)
			sdb_set (g->db, "agraph.curnode", a->title, 0);
	}
}

static ut64 rebase (RAGraph *g, int v) {
	return g->x < 0 ? -g->x + v : v;
}

static void agraph_set_layout(RAGraph *g, int is_interactive) {
	RListIter *it;
	RGraphNode *n;
	RANode *a;

	set_layout(g);

	if (is_interactive)
		set_curnode (g, find_near_of (g, NULL, R_TRUE));
	update_graph_sizes (g);
	graph_foreach_anode (r_graph_get_nodes (g->graph), it, n, a) {
		char *k;

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

	if (g->is_small_nodes)
		small_RANode_print(g, n, cur);
	else
		normal_RANode_print(g, n, cur);
}

static void agraph_print_nodes(const RAGraph *g) {
	const RList *nodes = r_graph_get_nodes (g->graph);
	RGraphNode *gn;
	RListIter *it;
	RANode *n;

	graph_foreach_anode (nodes, it, gn, n) {
		if (gn != g->curnode)
			agraph_print_node(g, n);
	}

	/* draw current node now to make it appear on top */
	if (g->curnode)
		agraph_print_node (g, get_anode (g->curnode));
}

static int find_ascii_edge (const AEdge *a, const AEdge *b) {
	return a->from == b->from && a->to == b->to ? 0 : 1;
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
	int is_first = R_TRUE;
	RCanvasLineStyle style;

	xinc = 3 + 2 * (nth + 1);
	x = a->x + xinc;
	y = a->y + a->h;
	if (nth > 1) nth = 1;

	switch (nth) {
	case 0: style.color = LINE_TRUE; break;
	case 1: style.color = LINE_FALSE; break;
	case -1: style.color = LINE_UNCJMP; break;
	}
	style.symbol = style.color;

	e.from = a;
	e.to = b;
	it = r_list_find (g->edges, &e, (RListComparator)find_ascii_edge);
	if (it) {
		int i, len;

		edg = r_list_iter_get_data (it);
		len = r_list_length (edg->x);

		for (i = 0; i < len; ++i) {
			x2 = (int)(size_t)r_list_get_n (edg->x, i);
			y2 = (int)(size_t)r_list_get_n (edg->y, i);

			if (is_first && nth == 0 && x2 > x) {
				xinc += 4;
				x += 4;
			}
			r_cons_canvas_line (g->can, x, y, x2, y2, &style);

			x = x2;
			y = y2;
			style.symbol = LINE_NONE;
			is_first = R_FALSE;
		}
	}

	x2 = b->x + xinc;
	y2 = b->y;
	if (is_first && nth == 0 && x2 > x) {
		xinc += 4;
		x += 4;
	}
	if (a == b) {
		x2 = a->x;
		y2 = y - 3;
	}
	r_cons_canvas_line (g->can, x, y, x2, y2, &style);
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

static void agraph_toggle_small_nodes(RAGraph *g) {
	g->is_small_nodes = !g->is_small_nodes;
	g->need_update_dim = R_TRUE;
	g->need_set_layout = R_TRUE;
}

static void agraph_toggle_simple_mode(RAGraph *g) {
	g->is_simple_mode = !g->is_simple_mode;
	g->need_reload_nodes = R_TRUE;
}

static void agraph_toggle_callgraph(RAGraph *g) {
	g->is_callgraph = !g->is_callgraph;
	g->need_reload_nodes = R_TRUE;
	g->force_update_seek = R_TRUE;
}

static void agraph_set_zoom (RAGraph *g, int v) {
	g->is_small_nodes = v <= 0;
	g->zoom = R_MAX (0, v);
	g->need_update_dim = R_TRUE;
	g->need_set_layout = R_TRUE;
}

/* reload all the info in the nodes, depending on the type of the graph
 * (callgraph, CFG, etc.), set the default layout for these nodes and center
 * the screen on the selected one */
static int agraph_reload_nodes(RAGraph *g, RCore *core, RAnalFunction *fcn) {
	r_agraph_reset (g);
	return reload_nodes(g, core, fcn);
}

static void follow_nth(RAGraph *g, int nth) {
	const RGraphNode *cn = r_graph_nth_neighbour (g->graph, g->curnode, nth);
	if (cn) {
		history_push (g->history, g->curnode);
		set_curnode (g, cn);
	}
}

static void agraph_follow_true(RAGraph *g) {
	follow_nth(g, 0);
	agraph_update_seek(g, get_anode (g->curnode), R_FALSE);
}

static void agraph_follow_false(RAGraph *g) {
	follow_nth(g, 1);
	agraph_update_seek(g, get_anode (g->curnode), R_FALSE);
}

/* go back in the history of selected nodes, if we can */
static void agraph_undo_node(RAGraph *g) {
	const RGraphNode *p = history_pop (g->history);
	if (p) {
		set_curnode (g, p);
		agraph_update_seek (g, p->data, R_FALSE);
	}
}

/* pushes the current node in the history and makes g->curnode the next node in
 * the order given by r_graph_get_nodes */
static void agraph_next_node(RAGraph *g) {
	history_push (g->history, g->curnode);
	set_curnode (g, find_near_of (g, g->curnode, R_TRUE));
	agraph_update_seek (g, get_anode (g->curnode), R_FALSE);
}

/* pushes the current node in the history and makes g->curnode the prev node in
 * the order given by r_graph_get_nodes */
static void agraph_prev_node(RAGraph *g) {
	history_push (g->history, g->curnode);
	set_curnode (g, find_near_of (g, g->curnode, R_FALSE));
	agraph_update_seek (g, get_anode (g->curnode), R_FALSE);
}

static void agraph_update_title (RAGraph *g, RAnalFunction *fcn) {
	char *new_title = r_str_newf(
			"[0x%08"PFMT64x"]> %d VV @ %s (nodes %d edges %d zoom %d%%) %s mouse:%s movements-speed:%d",
			fcn->addr, r_stack_size (g->history), fcn->name,
			g->graph->n_nodes, g->graph->n_edges, g->zoom, g->is_callgraph?"CG":"BB",
			mousemodes[mousemode], g->movspeed);
	r_agraph_set_title (g, new_title);
	r_str_free (new_title);
}

/* look for any change in the state of the graph
 * and update what's necessary */
static int check_changes (RAGraph *g, int is_interactive,
		RCore *core, RAnalFunction *fcn) {
	if (g->need_reload_nodes && core) {
		int ret = agraph_reload_nodes (g, core, fcn);
		if (!ret) return R_FALSE;
	}
	if (fcn)
		agraph_update_title (g, fcn);
	if (g->need_update_dim || g->need_reload_nodes || !is_interactive)
		update_node_dimension (g->graph, g->is_small_nodes, g->zoom);
	if (g->need_set_layout || g->need_reload_nodes || !is_interactive)
		agraph_set_layout (g, is_interactive);
	if (g->update_seek_on || g->force_update_seek) {
		RANode *n = g->update_seek_on;

		if (!n && g->curnode) n = get_anode (g->curnode);
		if (n) update_seek(g->can, n, g->force_update_seek);
	}

	g->need_reload_nodes = R_FALSE;
	g->need_update_dim = R_FALSE;
	g->need_set_layout = R_FALSE;
	g->update_seek_on = NULL;
	g->force_update_seek = R_FALSE;
	return R_TRUE;
}

static int agraph_print (RAGraph *g, int is_interactive,
                          RCore *core, RAnalFunction *fcn) {
	int h, w = r_cons_get_size (&h);
	int ret;

	ret = check_changes (g, is_interactive, core, fcn);
	if (!ret) return R_FALSE;

	if (is_interactive) {
		r_cons_clear00 ();
	}

	/* TODO: limit to screen size when the output is not redirected to file */
	if (!is_interactive)
		update_graph_sizes (g);

	h = is_interactive ? h : g->h + 1;
	w = is_interactive ? w : g->w;
	r_cons_canvas_resize (g->can, w, h);
	r_cons_canvas_clear (g->can);
	if (!is_interactive) {
		g->can->sx = -g->x;
		g->can->sy = -g->y + 1;
	}

	agraph_print_edges(g);
	agraph_print_nodes(g);

	/* print the graph title */
	(void)G (-g->can->sx, -g->can->sy);
	W (g->title);

	r_cons_canvas_print_region (g->can);

	if (is_interactive) {
		const char *cmdv;

		cmdv = r_config_get (core->config, "cmd.gprompt");
		if (cmdv && *cmdv) {
			r_cons_gotoxy (0, 1);
			r_core_cmd0 (core, cmdv);
		}
	}
	r_cons_flush ();
	return R_TRUE;
}

static int agraph_refresh(struct agraph_refresh_data *grd) {
	RCore *core = grd->core;
	RAGraph *g = grd->g;
	RAnalFunction **fcn = grd->fcn;
	RAnalFunction *f;

	/* allow to change the current function during debugging */
	if (g->is_instep && core->io->debug)
		r_core_cmd0 (core, "sr pc");

	f = r_anal_get_fcn_in (core->anal, core->offset, 0);
	if (f && f != *fcn) {
		*fcn = f;
		g->need_reload_nodes = R_TRUE;
		g->force_update_seek = R_TRUE;
	}

	return agraph_print (g, grd->fs, core, *fcn);
}

static void agraph_toggle_speed (RAGraph *g, RCore *core) {
	int alt = r_config_get_i (core->config, "graph.scroll");

	g->movspeed = g->movspeed == DEFAULT_SPEED ? alt : DEFAULT_SPEED;
}

static void agraph_init(RAGraph *g) {
	g->is_callgraph = R_FALSE;
	g->is_instep = R_FALSE;
	g->is_simple_mode = R_TRUE;
	g->is_small_nodes = R_FALSE;
	g->need_reload_nodes = R_TRUE;
	g->force_update_seek = R_TRUE;
	g->color_box = Color_RESET;
	g->color_box2 = Color_BLUE; // selected node
	g->color_box3 = Color_MAGENTA;
	g->history = r_stack_new (INIT_HISTORY_CAPACITY);
	g->graph = r_graph_new ();
	g->nodes = sdb_new0 ();
	g->zoom = ZOOM_DEFAULT;
	g->movspeed = DEFAULT_SPEED; //r_config_get_i (g->core->config, "graph.scroll");
	g->db = sdb_new0 ();
}

static void free_anode (RANode *n) {
	free (n->title);
	free (n->body);
}

static int free_anode_cb (void *user UNUSED, const char *k UNUSED, const char *v) {
	RANode *n = (RANode *)(size_t)sdb_atoi(v);
	free_anode (n);
	return 1;
}

static void agraph_free_nodes (const RAGraph *g) {
	sdb_foreach (g->nodes, (SdbForeachCallback)free_anode_cb, NULL);
	sdb_free (g->nodes);
}

static void sdb_set_enc (Sdb *db, const char *key, const char *v, ut32 cas) {
	char *estr = sdb_encode ((const void *)v, -1);
	sdb_set (db, key, estr, cas);
	free (estr);
}

static void agraph_sdb_init (const RAGraph *g) {
	sdb_bool_set (g->db, "agraph.is_callgraph", g->is_callgraph, 0);
	sdb_bool_set (g->db, "agraph.is_instep", g->is_instep, 0);

	sdb_set_enc (g->db, "agraph.color_box", g->color_box, 0);
	sdb_set_enc (g->db, "agraph.color_box2", g->color_box2, 0);
	sdb_set_enc (g->db, "agraph.color_box3", g->color_box3, 0);
	sdb_set_enc (g->db, "agraph.color_true", g->color_true, 0);
	sdb_set_enc (g->db, "agraph.color_false", g->color_false, 0);
}

R_API Sdb *r_agraph_get_sdb (RAGraph *g) {
	g->need_update_dim = R_TRUE;
	g->need_set_layout = R_TRUE;
	check_changes (g, R_FALSE, NULL, NULL);
	return g->db;
}

R_API void r_agraph_print (RAGraph *g) {
	agraph_print (g, R_FALSE, NULL, NULL);
	if (g->graph->n_nodes > 0)
		r_cons_newline ();
}

R_API void r_agraph_set_title (RAGraph *g, const char *title) {
	if (g->title) free (g->title);
	g->title = title ? strdup (title) : NULL;
	sdb_set (g->db, "agraph.title", g->title, 0);
}

R_API RANode *r_agraph_add_node (const RAGraph *g, const char *title,
                                 const char *body) {
	RANode *res;

	res = r_agraph_get_node (g, title);
	if (res) return res;

	res = R_NEW0 (RANode);
	if (!res) return NULL;
	res->title = title ? strdup(title) : strdup("");
	res->body = body ? strdup(body) : strdup("");
	res->layer = -1;
	res->pos_in_layer = -1;
	res->is_dummy = R_FALSE;
	res->is_reversed = R_FALSE;
	res->klass = -1;

	res->gnode = r_graph_add_node (g->graph, res);
	sdb_num_set (g->nodes, title, (ut64)(size_t)res, 0);
	if (res->title) {
		char *s, *estr, *b;
		size_t len;

		sdb_array_add (g->db, "agraph.nodes", res->title, 0);
		b = strdup (res->body);
		len = strlen (b);
		if (b[len - 1] == '\n') b[len - 1] = '\0';
		estr = sdb_encode ((const void *)b, -1);
		s = sdb_fmt (1, "base64:%s", estr);
		free (estr);
		free (b);
		sdb_set (g->db, sdb_fmt (2, "agraph.nodes.%s.body", res->title), s, 0);
	}
	return res;
}

static int user_node_cb (RANodeCallback cb, const char *k UNUSED,
		const char *v) {
	RANode *n = (RANode *)(size_t)sdb_atoi (v);
	if (n) cb (n);
	return 1;
}

static int user_edge_cb (struct g_cb *user, const char *k UNUSED,
		const char *v) {
	RAEdgeCallback cb = user->cb;
	RAGraph *g = user->graph;
	RANode *an, *n = (RANode *)(size_t)sdb_atoi (v);
	const RList *neigh = r_graph_get_neighbours (g->graph, n->gnode);
	RListIter *it;
	RGraphNode *gn;

	graph_foreach_anode (neigh, it, gn, an) {
		cb (n, an);
	}
	return 1;
}

R_API void r_agraph_foreach (RAGraph *g, RANodeCallback cb) {
	sdb_foreach (g->nodes, (SdbForeachCallback)user_node_cb, cb);
}

R_API void r_agraph_foreach_edge (RAGraph *g, RAEdgeCallback cb) {
	struct g_cb u;
	u.graph = g;
	u.cb = cb;
	sdb_foreach (g->nodes, (SdbForeachCallback)user_edge_cb, &u);
}

R_API RANode *r_agraph_get_node (const RAGraph *g, const char *title) {
	return (RANode *)(size_t)sdb_num_get (g->nodes, title, NULL);
}

R_API void r_agraph_add_edge (const RAGraph *g, RANode *a, RANode *b) {
	if (!g || !a || !b) return;
	r_graph_add_edge (g->graph, a->gnode, b->gnode);
	if (a->title && b->title) {
		char *k = sdb_fmt (1, "agraph.nodes.%s.neighbours", a->title);
		sdb_array_add (g->db, k, b->title, 0);
	}
}

R_API void r_agraph_add_edge_at (const RAGraph *g, RANode *a, RANode *b, int nth) {
	if (!g || !a || !b) return;
	if (a->title && b->title) {
		char *k = sdb_fmt (1, "agraph.nodes.%s.neighbours", a->title);
		sdb_array_insert (g->db, k, nth, b->title, 0);
	}
	r_graph_add_edge_at (g->graph, a->gnode, b->gnode, nth);
}

R_API void r_agraph_del_edge (const RAGraph *g, RANode *a, RANode *b) {
	if (!g || !a || !b) return;
	if (a->title && b->title) {
		char *k = sdb_fmt (1, "agraph.nodes.%s.neighbours", a->title);
		sdb_array_remove (g->db, k, b->title, 0);
	}
	r_graph_del_edge (g->graph, a->gnode, b->gnode);
}

R_API void r_agraph_reset (RAGraph *g) {
	r_graph_reset (g->graph);
	r_stack_free (g->history);
	agraph_free_nodes (g);
	r_agraph_set_title (g, NULL);
	sdb_reset (g->db);
	r_list_free (g->edges);

	g->nodes = sdb_new0 ();
	g->update_seek_on = NULL;
	g->x = g->y = g->w = g->h = 0;
	g->history = r_stack_new (INIT_HISTORY_CAPACITY);
	agraph_sdb_init (g);
	g->edges = r_list_new ();
}

R_API void r_agraph_free(RAGraph *g) {
	r_graph_free (g->graph);
	r_stack_free (g->history);
	if (g->edges) r_list_free (g->edges);
	agraph_free_nodes (g);
	r_agraph_set_title (g, NULL);
	sdb_free (g->db);
	free(g);
}

R_API RAGraph *r_agraph_new(RConsCanvas *can) {
	RAGraph *g = R_NEW0 (RAGraph);
	if (!g) return NULL;

	g->can = can;

	agraph_init(g);
	agraph_sdb_init (g);
	return g;
}

static void visual_offset (RCore *core) {
	char buf[256];
	int cols, rows;
	cols = r_cons_get_size (&rows);
	r_cons_gotoxy (0,rows);
	r_cons_flush ();
	r_line_set_prompt ("[offset]> ");
	strcpy (buf, "s ");
	if (r_cons_fgets (buf+2, sizeof (buf)-3, 0, NULL) > 0) {
		if (buf[2] == '.') buf[1]='.';
		r_core_cmd0 (core, buf);
	}
}

R_API int r_core_visual_graph(RCore *core, RAnalFunction *_fcn, int is_interactive) {
	int exit_graph = R_FALSE, is_error = R_FALSE;
	struct agraph_refresh_data *grd;
	int okey, key, wheel;
	RAnalFunction *fcn;
	const char *key_s;
	RConsCanvas *can;
	RAGraph *g;
	int wheelspeed;
	int w, h;
	int ret;
	int invscroll;

	fcn = _fcn? _fcn: r_anal_get_fcn_in (core->anal, core->offset, 0);
	if (!fcn) {
		eprintf ("No function in current seek\n");
		return R_FALSE;
	}
	w = r_cons_get_size (&h);
	can = r_cons_canvas_new (w, h);
	if (!can) {
		eprintf ("Cannot create RCons.canvas context\n");
		return R_FALSE;
	}
	can->linemode = 1;
	can->color = r_config_get_i (core->config, "scr.color");

	g = r_agraph_new (can);
	if (!g) {
		is_error = R_TRUE;
		goto err_graph_new;
	}
	g->movspeed = r_config_get_i (core->config, "graph.scroll");

	grd = R_NEW (struct agraph_refresh_data);
	grd->g = g;
	grd->fs = is_interactive;
	grd->core = core;
	grd->fcn = &fcn;

	core->cons->event_data = grd;
	core->cons->event_resize = (RConsEvent)agraph_refresh;

	while (!exit_graph && !is_error) {
		invscroll = r_config_get_i (core->config, "graph.invscroll");
		w = r_cons_get_size (&h);
		ret = agraph_refresh (grd);
		if (!ret) {
			is_error = R_TRUE;
			break;
		}

		if (!is_interactive) {
			/* this is a non-interactive ascii-art graph, so exit the loop */
			r_cons_newline ();
			break;
		}

		r_cons_show_cursor(R_FALSE);
		wheel = r_config_get_i (core->config, "scr.wheel");
		if (wheel)
			r_cons_enable_mouse (R_TRUE);

		// r_core_graph_inputhandle()
		okey = r_cons_readchar ();
		key = r_cons_arrow_to_hjkl (okey);
		wheelspeed = r_config_get_i (core->config, "scr.wheelspeed");

		switch (key) {
		case '-':
			agraph_set_zoom (g, g->zoom - ZOOM_STEP);
			break;
		case '+':
			agraph_set_zoom (g, g->zoom + ZOOM_STEP);
			break;
		case '0':
			agraph_set_zoom (g, ZOOM_DEFAULT);
			agraph_update_seek (g, get_anode (g->curnode), R_TRUE);
			break;
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
			agraph_toggle_simple_mode(g);
			break;
		case 'V':
			agraph_toggle_callgraph(g);
			break;
		case 'z':
			g->is_instep = R_TRUE;
			key_s = r_config_get (core->config, "key.s");
			if (key_s && *key_s) {
				r_core_cmd0 (core, key_s);
			} else {
				if (r_config_get_i (core->config, "cfg.debug"))
					r_core_cmd0 (core, "ds;.dr*");
				else
					r_core_cmd0 (core, "aes;.dr*");
			}
			g->need_reload_nodes = R_TRUE;
			break;
		case 'Z':
			if (okey == 27) {
				agraph_prev_node(g);
			} else {
				// 'Z'
				g->is_instep = R_TRUE;
				if (r_config_get_i (core->config, "cfg.debug"))
					r_core_cmd0 (core, "dso;.dr*");
				else r_core_cmd0 (core, "aeso;.dr*");
				g->need_reload_nodes = R_TRUE;
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
			agraph_next_node (g);
			break;
		case '?':
			r_cons_clear00 ();
			r_cons_printf ("Visual Ascii Art graph keybindings:\n"
					" .      - center graph to the current node\n"
					" !      - toggle scr.color\n"
					" hjkl   - move node\n"
					" HJKL   - scroll canvas\n"
					" tab    - select next node\n"
					" TAB    - select previous node\n"
					" t/f    - follow true/false edges\n"
					" e      - toggle edge-lines style (diagonal/square)\n"
					" O      - toggle disasm mode\n"
					" r      - relayout\n"
					" R      - randomize colors\n"
					" o      - go/seek to given offset\n"
					" u/U    - undo/redo seek\n"
					" p      - toggle mini-graph\n"
					" b      - select previous node\n"
					" V      - toggle basicblock / call graphs\n"
					" w      - toggle between movements speed 1 and graph.scroll\n"
					" x/X    - jump to xref/ref\n"
					" z/Z    - step / step over\n"
					" +/-/0  - zoom in/out/default\n");
			r_cons_flush ();
			r_cons_any_key (NULL);
			break;
		case 'o':
			visual_offset (core);
			break;
		case 'u':
			{
			ut64 off = r_io_sundo (core->io, core->offset);
			if (off != UT64_MAX)
				r_core_seek (core, off, 1);
			else eprintf ("Can not undo\n");
			}
			break;
		case 'U':
			{
			ut64 off = r_io_sundo_redo (core->io);
			if (off != UT64_MAX)
				r_core_seek (core,off, 1);
			else eprintf ("Can not redo\n");
			break;
			}
		case 'R':
			r_core_cmd0 (core, "ecr");
			g->color_box = core->cons->pal.graph_box;
			g->color_box2 = core->cons->pal.graph_box2;
			g->color_box3 = core->cons->pal.graph_box3;
			g->color_true = core->cons->pal.graph_true;
			g->color_false = core->cons->pal.graph_false;
			/* TODO: reload only the body of the nodes to update colors */
			break;
		case '!':
		{
			/* TODO: remove this option once the colored are "stable" */
			int colors = r_config_get_i (core->config, "scr.color");
			r_config_set_i (core->config, "scr.color", !colors);
			g->need_reload_nodes = R_TRUE;
			break;
		}
		case 'r':
			agraph_set_layout (g, R_TRUE);
			break;
		case 'j':
			if (r_cons_singleton()->mouse_event) {
				switch (mousemode) {
				case 0: can->sy += wheelspeed * (invscroll ? -1 : 1); break; // canvas-y
				case 1: can->sx += wheelspeed * (invscroll ? -1 : 1); break; // canvas-x
				case 2: get_anode(g->curnode)->y += wheelspeed; break; // node-y
				case 3: get_anode(g->curnode)->x += wheelspeed; break; // node-x
				}
			} else {
				get_anode(g->curnode)->y += g->movspeed;
			}
			break;
		case 'k':
			if (r_cons_singleton()->mouse_event) {
				switch (mousemode) {
				case 0: can->sy -= wheelspeed * (invscroll ? -1 : 1); break; // canvas-y
				case 1: can->sx -= wheelspeed * (invscroll ? -1 : 1); break; // canvas-x
				case 2: get_anode(g->curnode)->y -= wheelspeed; break; // node-y
				case 3: get_anode(g->curnode)->x -= wheelspeed; break; // node-x
				}
			} else {
				get_anode(g->curnode)->y -= g->movspeed;
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
		case 'h': get_anode(g->curnode)->x -= g->movspeed; break;
		case 'l': get_anode(g->curnode)->x += g->movspeed; break;

		case 'K': can->sy -= g->movspeed * (invscroll ? -1 : 1); break;
		case 'J': can->sy += g->movspeed * (invscroll ? -1 : 1); break;
		case 'H': can->sx -= g->movspeed * (invscroll ? -1 : 1); break;
		case 'L': can->sx += g->movspeed * (invscroll ? -1 : 1); break;
		case 'e':
			  can->linemode = !!!can->linemode;
			  break;
		case 'p':
			  agraph_toggle_small_nodes (g);
			  agraph_update_seek (g, get_anode (g->curnode), R_TRUE);
			  break;
		case 'b':
			  agraph_undo_node(g);
			  break;
		case '.':
			  agraph_update_seek (g, get_anode (g->curnode), R_TRUE);
			  g->is_instep = R_TRUE;
			  break;
		case 't':
			  agraph_follow_true (g);
			  break;
		case 'f':
			  agraph_follow_false (g);
			  break;
		case '/':
			  r_core_cmd0 (core, "?i highlight;e scr.highlight=`?y`");
			  break;
		case ':':
			  core->vmode = R_FALSE;
			  r_core_visual_prompt_input (core);
			  core->vmode = R_TRUE;
			  break;
		case 'w':
			  agraph_toggle_speed (g, core);
			  break;
		case -1: // EOF
		case 'q':
			  if (g->is_callgraph) {
				  agraph_toggle_callgraph(g);
			  } else exit_graph = R_TRUE;
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

	core->cons->event_data = NULL;
	core->cons->event_resize = NULL;

	free (grd);
	r_agraph_free(g);
err_graph_new:
	r_config_set_i (core->config, "scr.color", can->color);
	r_cons_canvas_free (can);
	return !is_error;
}
