/* radare - LGPL - Copyright 2007-2012 - pancake */
/* graph with stack facilities implementation */

#include <r_util.h>

#if 0
RGraph *r_anal_getgraph(RAnal *anal, ut64 addr) {
        RGraph *g;
        RFunction *f = r_anal_fcn_get (anal, addr);
        if (!f) return NULL;
        g = r_graph_new ();
        // walk basic blocks, and create nodes and edges
}

// r_anal_graph_to_kv()
node.0x804840={"name":"patata",size:123,"code":"jlasdfjlksf"}
node.0x804840.to=[0x804805,0x804805,0x0485085,0x90850]
#endif

R_API RGraphNode *r_graph_node_new (ut64 addr, void *data) {
	RGraphNode *p = R_NEW0 (RGraphNode);
	p->parents = r_list_new ();
	p->children = r_list_new ();
	p->addr = addr;
	p->data = data;
	p->refs = 0;
	return p;
}

R_API void r_graph_node_free (RGraphNode *n) {
	r_list_free (n->parents);
	r_list_free (n->children);
	if (n->free)
		n->free (n->data);
	free (n);
}

static void walk_children (RGraph *t, RGraphNode *tn, int level) {
	int i;
	RListIter *iter;
	RGraphNode *n;
	if (r_list_contains (t->path, tn)) {
		// do not repeat pushed nodes
		return;
	}
	for (i=0; i<level; i++)
		t->printf ("   ");
	t->printf (" 0x%08"PFMT64x" refs %d\n",
			tn->addr, tn->refs);
	r_list_foreach (tn->parents, iter, n) {
		for (i=0; i<level; i++)
			t->printf ("   ");
		t->printf (" |_ 0x%08"PFMT64x"\n", n->addr);
	}
	r_list_push (t->path, tn);
	r_list_foreach (tn->children, iter, n) {
		walk_children (t, n, level+1);
	}
	r_list_pop (t->path);
}

R_API void r_graph_traverse(RGraph *t) {
	RListIter *iter;
	RGraphNode *root;
	RList *path = t->path;
	t->path = r_list_new ();
	r_list_foreach (t->roots, iter, root) {
		walk_children (t, root, 0);
	}
	r_list_free (t->path);
	t->path = path;
}

R_API RGraph* r_graph_new () {
	RGraph *t = R_NEW0 (RGraph);
	t->printf = (PrintfCallback) printf;
	t->path = r_list_new ();
	t->nodes = r_list_new ();
	t->roots = r_list_new ();
	t->nodes->free = (RListFree)r_graph_node_free;
	t->root = NULL;
	t->cur = NULL;
	return t;
}

R_API void r_graph_free (RGraph* t) {
	r_list_free (t->nodes);
	r_list_free (t->path);
	r_list_free (t->roots);
	free (t);
}

R_API RGraphNode* r_graph_get_current (RGraph *t, ut64 addr) {
	return t->cur? t->cur->data: NULL;
}

R_API RGraphNode* r_graph_get_node (RGraph *t, ut64 addr, boolt c) {
	RListIter *iter;
	RGraphNode *n;
	r_list_foreach (t->nodes, iter, n) {
		if (n->addr == addr)
			return n;
	}
	if (c) {
		n = r_graph_node_new (addr, NULL);
		r_list_append (t->nodes, n);
		return n;
	}
	return NULL;
}

R_API void r_graph_reset (RGraph *t) {
	r_list_free (t->nodes);
	t->nodes = r_list_new ();
	t->nodes->free = (RListFree)r_graph_node_free;
	r_list_free (t->roots);
	t->roots = r_list_new ();
	t->root = NULL;
}

// g.add (0x804840, 0x804408, null);
R_API void r_graph_add (RGraph *t, ut64 from, ut64 addr, void *data) {
	RGraphNode *n, *f = r_graph_get_node (t, from, R_TRUE);
	n = r_graph_get_node (t, addr, R_TRUE);
	n->data = data;
	if (!r_list_contains (f->children, n))
		r_list_append (f->children, n);
	if (!r_list_contains (f->parents, n))
		r_list_append (n->parents, f);
}

// plant: to set new root :)
R_API void r_graph_plant(RGraph *t) {
	t->root = NULL;
}

R_API void r_graph_push (RGraph *t, ut64 addr, void *data) {
	RGraphNode *c, *n = r_graph_get_node (t, addr, R_FALSE);
	t->level++;
	if (!n) {
		n = r_graph_node_new (addr, data);
		r_list_append (t->nodes, n);
		if (t->root == NULL) {
			t->root = n;
			r_list_append (t->roots, n);
		}
	} else {
		n->refs++;
		n->data = data; // update data if already pushed?
	}
	if (!t->cur)
		t->cur = r_list_contains (t->nodes, n);
	if (t->cur) {
		c = t->cur->data;
		if (!r_list_contains (c->children, n))
			r_list_append (c->children, n);
		if (c->addr && !r_list_contains (n->parents, c))
			r_list_append (n->parents, c);

	}
	t->cur = r_list_append (t->path, n);
}

R_API RGraphNode* r_graph_pop(RGraph *t) {
	RListIter *p;
	if (!t || !t->path || !t->cur)
		return NULL;
	// TODO: handle null
	t->level--;
	if (t->level<0) {
		eprintf ("Negative pop!\n");
		return NULL;
	}
	p = t->cur->p;
	r_list_delete (t->path, t->cur);
	t->cur = p;
	return (RGraphNode*)t->cur;
}

#if TEST
// usage
main () {
	RGraph *t = r_graph_new ();
	r_graph_push (t, 0x8048590, NULL);
	r_graph_push (t, 0x8048230, NULL);
	r_graph_pop (t);
	r_graph_push (t, 0x8044300, NULL);
	r_graph_push (t, 0x8046300, NULL);
	r_graph_pop (t);
	r_graph_push (t, 0x8046388, NULL);
	r_graph_pop (t);
	r_graph_push (t, 0x8046388, NULL);
	r_graph_push (t, 0x8046388, NULL);
		r_graph_push (t, 0x8046300, NULL);
		r_graph_push (t, 0x8046300, NULL);
	r_graph_pop (t);
	r_graph_traverse (t);
	r_graph_free (t);
}
#endif
