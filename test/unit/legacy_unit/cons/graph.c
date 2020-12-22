/* Copyright radare2 2014 - Author: pancake */

#include <r_cons.h>

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

int curnode = 0;

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

main() {
	int w, h, i;
	RConsCanvas *can;
	RCons *c = r_cons_new ();
	w = r_cons_get_size (&h);
	can = r_cons_canvas_new (w-1, h-1);
repeat:
	r_cons_canvas_clear (can);

	for (i=0;edges[i].nth!=-1;i++) {
		Node *a = &nodes[edges[i].from];
		Node *b = &nodes[edges[i].to];
		Edge_print (can, a, b, edges[i].nth);
	}
	for (i=0;nodes[i].text;i++) {
		Node_print (can, &nodes[i], i==curnode);
	}
	//r_cons_canvas_line (can, 12, 4+5, X+5, 5, 0);

	r_cons_canvas_print (can);
	r_cons_flush ();
	int key = r_cons_readchar ();
#define N nodes[curnode]
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
	case 'q': exit(0);
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
	}
	goto repeat;
	r_cons_free (c);
}
