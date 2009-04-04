/* radare - LGPL - Copyright 2009 pancake<nopcode.org> */

#include <btree.h>

R_API void btree_init(struct btree_node **T)
{
	*T = NULL;
}

R_API struct btree_node *btree_remove(struct btree_node *p, BTREE_DEL(del))
{
	struct btree_node *rp = NULL, *f;
	if (p==NULL) return p;
	if (p->right!=NULL) {
		if (p->left!=NULL) {
			f = p;
			rp = p->right;
			while(rp->left!=NULL) {
				f = rp;
				rp = rp->left;
			}
			if (f!=p) {
				f->left = rp->right;
				rp->right = p->right;
				rp->left = p->left;
			} else rp->left = p->left;
		} else rp = p->right;
	} else rp = p->left;
	if (del) del(p->data);
	free(p);
	return(rp);
}

R_API void *btree_search(struct btree_node *proot, void *x, BTREE_CMP(cmp), int parent)
{
	struct btree_node *p = NULL;

	if (proot!=NULL) {
		p = proot;
		if (cmp (x, proot->data)<0)
			p = btree_search (proot->left, x, cmp, parent);
		else if (cmp(x, proot->data)>0)
			p = btree_search (proot->right, x, cmp, parent);
	}
	/* node found */
	if (p) {
		if (parent)
			return proot;
		return p;
	} return NULL;
}

R_API int btree_del(struct btree_node *proot, void *x, BTREE_CMP(cmp), BTREE_DEL(del))
{
	struct btree_node *p = btree_search (proot, x, cmp, 1);
	if (p) {
		p->right = btree_remove (p->left, del);
		return 1;
	}
	return 0;
}

R_API void *btree_get(struct btree_node *proot, void *x, BTREE_CMP(cmp))
{
	struct btree_node *p = btree_search (proot, x, cmp, 0);
	if (p) {
		p->hits++;
		return p->data;
	}
	return NULL;
}

R_API void btree_cleartree(struct btree_node *proot, BTREE_DEL(del))
{
	if (proot!=NULL) {
		btree_cleartree (proot->left, del);
		btree_cleartree (proot->right, del);
		if (del) del (proot->data);
		free (proot);
	}
}

R_API void btree_insert(struct btree_node *p,struct btree_node **T, BTREE_CMP(cmp))
{
	int ret = cmp (p->data,(*T)->data);
	if (ret<0) {
		if ((*T)->left) btree_insert (p, &(*T)->left, cmp);
		else (*T)->left=p;
	} else if (ret>0) {
		if ((*T)->right) btree_insert (p, &(*T)->right, cmp);
		else (*T)->right=p;
	}
}

R_API void btree_add(struct btree_node **T, void *e, BTREE_CMP(cmp))
{
	struct btree_node *p = (struct btree_node*)
		malloc(sizeof(struct btree_node));
	p->data = e;
	p->hits = 0;
	p->left = p->right = NULL;
	if (*T==NULL) *T = p;
	else btree_insert (p, T, cmp);
}

/*--------------------*/

#if MAIN

struct mydata {
	unsigned long long addr;
	char *str;
};

int shownode(char *str, struct mydata *m)
{
	if (m == NULL)
		printf("==> not found\n");
	else printf("==> %s: %s, %lld\n", str, m->str, m->addr);
	return 0;
}
int mycmp(const void *a, const void *b)
{
	struct mydata *ma = (struct mydata *)a;
	struct mydata *mb = (struct mydata *)b;
	if (a==NULL || b == NULL)
		return 0;
	return (int)(ma->addr-mb->addr);
}

int main()
{
	struct btree_node *bt = NULL;
	//btree_init(&bt);

	struct mydata foo = { 10, "hello" };
	struct mydata bar = { 20, "world" };
	btree_add(&bt, &foo, mycmp);
	btree_add(&bt, &bar, mycmp);

printf("==== go search ====\n");
	/* find existent data */
	struct mydata *p = btree_get(bt, &bar, mycmp);
	shownode("result for 20: ", p);

printf("==== go search ====\n");
	/* find unexistent data */
	struct mydata nop = { 15, NULL };
	p = btree_get(bt, &nop, mycmp);
	shownode("result for 15: ", p);

#if 1
printf("==== go remove 20 ====\n");
	if (btree_del(bt, &bar, mycmp, NULL))
		printf("node found and removed\n");
	else printf("oops\n");
#endif

printf("==== go search ====\n");
	/* find existent data */
	p = btree_get(bt, &bar, mycmp);
	shownode("result for 20: ", p);

printf("==== go search ====\n");
	/* find existent data */
	p = btree_get(bt, &foo, mycmp);
	shownode("result for 10: ", p);

	btree_cleartree(bt, NULL);
	return 0;
}
#endif
