/* Copyright radare2 2014 - Author: pancake */

#include <r_core.h>

typedef struct {
	int x;
	int y;
	int w;
	int h;
	ut64 addr;
	const char *text;
} Node;

typedef struct {
	int nth;
	int from;
	int to;
} Edge;

static int curnode = 0;

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

#define G(x,y) r_cons_canvas_gotoxy (can, x, y)
#define W(x) r_cons_canvas_write (can, x)
#define B(x,y,w,h) r_cons_canvas_box(can, x,y,w,h)
#define L(x,y,x2,y2) r_cons_canvas_line(can, x,y,x2,y2,0)
#define F(x,y,x2,y2,c) r_cons_canvas_fill(can, x,y,x2,y2,c,0)

static void Node_print(RConsCanvas *can, Node *n, int cur) {
	char title[128];

	n->w = r_str_bounds (n->text, &n->h);
	n->w += 4;
	n->h += 4;
	n->w = R_MAX(18, n->w);
	if (cur) {
		F (n->x,n->y, n->w, n->h, '.');
		snprintf (title, sizeof (title)-1,
			"-[ 0x%08"PFMT64x" ]-", n->addr);
	} else {
		snprintf (title, sizeof (title)-1,
			"   0x%08"PFMT64x"   ", n->addr);
	}
	G (n->x+1, n->y+1);
	W (title);
	G (n->x+2, n->y+2);
	W (n->text);
	G (n->x+1, n->y+1);
	W (title);
	B (n->x, n->y, n->w, n->h);
}

static void Edge_print(RConsCanvas *can, Node *a, Node *b, int nth) {
	int x, y, x2, y2;
	int xinc = 3+(nth*3);
	x = a->x+xinc;
	y = a->y+a->h;
	x2 = b->x+xinc;
	y2 = b->y;
	L(x,y,x2,y2);
}

static int Edge_node(Edge *edges, int cur, int nth) {
	int i;
	for (i=0; edges[i].nth!=-1; i++) {
		if (edges[i].nth == nth)
			if (edges[i].from == cur)
				return edges[i].to;
	}
	return -1;
}

static int Node_find(const Node* nodes, ut64 addr) {
	int i;
	for (i=0; nodes[i].text; i++) {
		if (nodes[i].addr == addr)
			return i;
	}
	return -1;
}

R_API int r_core_visual_graph(RCore *core, RAnalFunction *_fcn) {
	RAnalFunction *fcn;
	RConsCanvas *can;
	RListIter *iter;
	RAnalBlock *bb;
	Node *nodes;
	Edge *edges;
	int w, h, i, n_nodes, n_edges;
	char title[128];

	fcn = _fcn?_fcn:r_anal_get_fcn_at (core->anal, core->offset);
	if (!fcn) {
		eprintf ("No function in current seek\n");
		return R_FALSE;
	}
	w = r_cons_get_size (&h);
	can = r_cons_canvas_new (w-1, h-1);

	nodes = malloc (sizeof(Node)*(r_list_length (fcn->bbs)+1));
	edges = NULL;
	i = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		nodes[i].text = r_core_cmd_strf (core,
			"pI %d @ 0x%08"PFMT64x, bb->size, bb->addr);
		nodes[i].addr = bb->addr;
		nodes[i].x = 10;
		nodes[i].y = 3;
		nodes[i].w = 0;
		nodes[i].h = 0;
		i++;
	}
	nodes[i].text = NULL;
	n_nodes = i;

	i = 0;
	n_edges = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		// add edge from bb->addr to bb->jump / bb->fail
		if (bb->jump != UT64_MAX) {
			n_edges++;
			edges = realloc(edges, sizeof (Edge)*(n_edges+1));
			edges[i].nth = 0;
			edges[i].from = Node_find (nodes, bb->addr);
			edges[i].to = Node_find (nodes, bb->jump);
			i++;
			if (bb->fail != UT64_MAX) {
				n_edges++;
				edges = realloc(edges, sizeof (Edge)*(n_edges+1));
				edges[i].nth = 1;
				edges[i].from = Node_find (nodes, bb->addr);
				edges[i].to = Node_find (nodes, bb->fail);
				i++;
			}
		}
	}
	edges[i].nth = -1;
repeat:
#if RESIZE_CANVAS
	w = r_cons_get_size (&h);
	can = r_cons_canvas_resize (w-1, h-1);
#endif
	r_cons_canvas_clear (can);

	if (edges)
	for (i=0;edges[i].nth!=-1;i++) {
		if (edges[i].from == -1 || edges[i].to == -1)
			continue;
		Node *a = &nodes[edges[i].from];
		Node *b = &nodes[edges[i].to];
		Edge_print (can, a, b, edges[i].nth);
	}
	if (nodes)
	for (i=0;nodes[i].text;i++) {
		Node_print (can, &nodes[i], i==curnode);
	}

	G (0,0);
	snprintf (title, sizeof(title)-1, "[0x%08"PFMT64x"]> VV @ %s (nodes %d)",
		fcn->addr, fcn->name, n_nodes);
	W (title);

	r_cons_canvas_print (can);
	r_cons_flush ();
	int key = r_cons_readchar ();
#define N nodes[curnode]
	int prevnode = curnode;
	switch (key) {
	case 9: curnode++;
		if (!nodes[curnode].text)
			curnode = 0;
		break;
	case 'j': N.y++; break;
	case 'k': N.y--; break;
	case 'h': N.x--; break;
	case 'l': N.x++; break;
	case 'J': N.y+=2; break;
	case 'K': N.y-=2; break;
	case 'H': N.x-=2; break;
	case 'L': N.x+=2; break;
	case 'u': 
		curnode = prevnode;
		break;
	case 't': 
		curnode = Edge_node(edges, curnode, 0);
		// select jump node
		break;
	case 'f': 
		curnode = Edge_node(edges, curnode, 1);
		// select false node
		break;
	case 'q': return R_TRUE;
	case 27: // ESC
		if (r_cons_readchar () == 91) {
			if (r_cons_readchar () == 90) {
				if (curnode<1) {
					int i;
					for(i=0;nodes[i].text;i++){};
					curnode = i-1;
				} else curnode--;
			}
		}
		break;
	default:
		eprintf ("Key %d\n", key);
		sleep (1);
		break;
	}
	goto repeat;
}
