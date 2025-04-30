/* radare - LGPL - Copyright 2022-2024 bemodtwz */

#include <r_search.h>
#include "search.h"

struct r_tire_node;

// not using r2 tree b/c this will probably be made fater in future
typedef struct r_tire_node {
	ut8 *data; // always borrows pointer
	ut32 len; // len of data, not necissarily str
	struct r_tire_node *next;
	struct r_tire_node *deeper;
	RSearchKeyword *kw; // populated iff this is a leaf, otherwise NULL, borrowed
} RTireNode;

// frees node and all linked nodes
static void node_free(RTireNode *node) {
	while (node) {
		node_free (node->deeper);
		RTireNode *n = node;
		node = node->next;
		free (n);
	}
}

static void free_root(RTireNode **root) {
	int i;
	for (i = 0; i < 255; i++) {
		node_free (root[i]);
	}
}

static inline RTireNode *new_node(void) {
	return R_NEW0 (RTireNode);
}

static inline RTireNode *new_leaf(RSearchKeyword *kw, ut8 *data, ut32 len) {
	R_RETURN_VAL_IF_FAIL (data, NULL);
	RTireNode *t = new_node ();
	if (t) {
		t->data = data;
		t->len = len;
		t->kw = kw;
	}
	return t;
}

// traverse *node and add kw to it
static inline bool add_node(RTireNode **root, RSearchKeyword *kw) {
	R_RETURN_VAL_IF_FAIL (kw && kw->keyword_length >= 1, false);
	R_RETURN_VAL_IF_FAIL (!kw->bin_binmask, false); // remove when binmake is supported

	ut8 *data = kw->bin_keyword;
	RTireNode **writeto = &root[*data];
	ut32 len = kw->keyword_length - 1;
	data++;

	while (*writeto) { // loop through nodes
		RTireNode *node = *writeto;
		R_RETURN_VAL_IF_FAIL (node->data, false); // sanity

		// get number of bytes in common
		ut32 comm, max = R_MIN (len, node->len);
		for (comm = 0; comm < max; comm++) {
			if (node->data[comm] != *data) {
				break;
			}
			data++;
			len--;
		}

		if (comm == node->len) {
			// matches, go deeper
			writeto = &node->deeper;
		} else if (comm == 0) {
			// does not match, check next
			writeto = &node->next;
		} else if (!len) {
			// keyword is a substring of node->data, so it must go above and node go deeper
			RTireNode *new = new_leaf (kw, node->data, comm);
			if (new) {
				node->data += comm;
				node->len -= comm;
				new->deeper = node;

				*writeto = new;
				writeto = &node->next;
				return true;
			}
		} else {
			// new node put before current node
			RTireNode *new = new_node ();
			if (!new) {
				return false;
			}
			new->data = node->data;
			new->len = comm;
			new->next = node->next;

			node->data += comm;
			node->len -= comm;
			node->next = NULL;

			*writeto = new;
			new->deeper = node;
			writeto = &node->next;
		}
	}

	*writeto = new_leaf (kw, data, len);
	return *writeto? true: false;
}

static inline int build_tire(RSearch *srch, RTireNode **root) {
	// build tire
	RSearchKeyword *kw;
	RListIter *iter;
	ut32 max = 0;
	r_list_foreach (srch->kws, iter, kw) {
		if (kw->icase) {
			R_LOG_ERROR ("Tire search can't ignore case yet");
			return -1;
		}
		if (!add_node (root, kw)) {
			R_LOG_ERROR ("Failed to build tire");
			return UT32_MAX;
		}
		if (max < kw->keyword_length) {
			max = kw->keyword_length;
		}
	}
	return max;
}

R_IPI int search_tire(RSearch *srch, ut64 from, ut64 to) {
	R_RETURN_VAL_IF_FAIL (r_list_length (srch->kws) > 0, -1);

	RTireNode *_root[256] = { 0 };
	RTireNode **root = _root;
	ut32 maxkey = build_tire (srch, root);

	if (!maxkey || maxkey == UT32_MAX) {
		printf ("Failed to build tire\n");
		return -1;
	}

	// build buffer
	const ut32 maxbuf = R_MAX (0x1000, maxkey * 2);
	ut64 addr = from;
	ut32 blen = R_MIN (maxbuf, to - from);
	ut8 *buf = malloc (blen);
	if (!buf || !srch->iob.read_at (srch->iob.io, from, buf, blen)) {
		free (buf);
		return -1;
	}

	int hits = 0;
	while (blen > maxkey) {
		ut8 *finger = buf; // point at next possible match
		ut8 *finger_end = buf + (blen - maxkey);
		for (finger = buf; finger + 1 < finger_end; finger++) {
			RTireNode *node = root[*finger];
			ut8 *b = finger + 1; // matching substrings of finger as you walk tire
			while (node && b < finger_end) {
				int remaining = finger_end - b;
				if (remaining < 1 || node->len >= remaining) {
					break;
				}
				if (!memcmp (node->data, b, node->len)) {
					// matches and it has a kw
					if (node->kw) {
						ut64 diff = finger - buf;
						/* printf ("dist: 0x%lx 0x%lx HIT: %s\n", diff, addr + diff, finger); // DENNIS */
						int t = r_search_hit_sz (srch, node->kw, addr + diff, node->kw->keyword_length);
						hits++;
						if (!t || t > 1) {
							free (buf);
							free_root (root);
							return t? hits: -1;
						}
					}
					// could be another substring match
					b += node->len;
					node = node->deeper;
				} else {
					node = node->next;
				}
			}
		}
		if (finger == buf) {
			finger++;
		}

		//  printf ("finished searching 0x%lx bytes from 0x%lx", finger - buf, addr); // DENNIS
		addr += finger - buf;
		if (addr >= to - maxkey || srch->consb.is_breaked (srch->consb.cons)) {
			break;
		}
		// printf ("Next up, addr 0x%lx", addr); // DENNIS

		// move leftover to start of buffer, and fill the rest
		memmove (buf, finger, maxkey);
		blen = R_MIN (maxbuf, to - addr);
		if (!srch->iob.read_at (srch->iob.io, addr + maxkey, buf + maxkey, blen - maxkey)) {
			free (buf);
			return -1;
		}
	}

	free (buf);
	free_root (root);
	return 0;
}
