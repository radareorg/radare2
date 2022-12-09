#include "jsi.h"
#include "jsvalue.h"

#include <assert.h>

/*
	Use an AA-tree to quickly look up properties in objects:

	The level of every leaf node is one.
	The level of every left child is one less than its parent.
	The level of every right child is equal or one less than its parent.
	The level of every right grandchild is less than its grandparent.
	Every node of level greater than one has two children.

	A link where the child's level is equal to that of its parent is called a horizontal link.
	Individual right horizontal links are allowed, but consecutive ones are forbidden.
	Left horizontal links are forbidden.

	skew() fixes left horizontal links.
	split() fixes consecutive right horizontal links.
*/

static js_Property sentinel = {
	&sentinel, &sentinel,
	0, 0,
	{ {0}, {0}, JS_TUNDEFINED },
	NULL, NULL, ""
};

static js_Property *newproperty(js_State *J, js_Object *obj, const char *name)
{
	int n = strlen(name) + 1;
	js_Property *node = js_malloc(J, offsetof(js_Property, name) + n);
	node->left = node->right = &sentinel;
	node->level = 1;
	node->atts = 0;
	node->value.type = JS_TUNDEFINED;
	node->value.u.number = 0;
	node->getter = NULL;
	node->setter = NULL;
	memcpy(node->name, name, n);
	++obj->count;
	++J->gccounter;
	return node;
}

static js_Property *lookup(js_Property *node, const char *name)
{
	while (node != &sentinel) {
		int c = strcmp(name, node->name);
		if (c == 0)
			return node;
		else if (c < 0)
			node = node->left;
		else
			node = node->right;
	}
	return NULL;
}

static js_Property *skew(js_Property *node)
{
	if (node->left->level == node->level) {
		js_Property *temp = node;
		node = node->left;
		temp->left = node->right;
		node->right = temp;
	}
	return node;
}

static js_Property *split(js_Property *node)
{
	if (node->right->right->level == node->level) {
		js_Property *temp = node;
		node = node->right;
		temp->right = node->left;
		node->left = temp;
		++node->level;
	}
	return node;
}

static js_Property *insert(js_State *J, js_Object *obj, js_Property *node, const char *name, js_Property **result)
{
	if (node != &sentinel) {
		int c = strcmp(name, node->name);
		if (c < 0)
			node->left = insert(J, obj, node->left, name, result);
		else if (c > 0)
			node->right = insert(J, obj, node->right, name, result);
		else
			return *result = node;
		node = skew(node);
		node = split(node);
		return node;
	}
	return *result = newproperty(J, obj, name);
}

static void freeproperty(js_State *J, js_Object *obj, js_Property *node)
{
	js_free(J, node);
	--obj->count;
}

static js_Property *unlinkproperty(js_Property *node, const char *name, js_Property **garbage)
{
	js_Property *temp, *a, *b;
	if (node != &sentinel) {
		int c = strcmp(name, node->name);
		if (c < 0) {
			node->left = unlinkproperty(node->left, name, garbage);
		} else if (c > 0) {
			node->right = unlinkproperty(node->right, name, garbage);
		} else {
			*garbage = node;
			if (node->left == &sentinel && node->right == &sentinel) {
				return &sentinel;
			}
			else if (node->left == &sentinel) {
				a = node->right;
				while (a->left != &sentinel)
					a = a->left;
				b = unlinkproperty(node->right, a->name, &temp);
				temp->level = node->level;
				temp->left = node->left;
				temp->right = b;
				node = temp;
			}
			else {
				a = node->left;
				while (a->right != &sentinel)
					a = a->right;
				b = unlinkproperty(node->left, a->name, &temp);
				temp->level = node->level;
				temp->left = b;
				temp->right = node->right;
				node = temp;
			}
		}

		if (node->left->level < node->level - 1 || node->right->level < node->level - 1)
		{
			if (node->right->level > --node->level)
				node->right->level = node->level;
			node = skew(node);
			node->right = skew(node->right);
			node->right->right = skew(node->right->right);
			node = split(node);
			node->right = split(node->right);
		}
	}
	return node;
}

static js_Property *deleteproperty(js_State *J, js_Object *obj, js_Property *tree, const char *name)
{
	js_Property *garbage = &sentinel;
	tree = unlinkproperty(tree, name, &garbage);
	if (garbage != &sentinel)
		freeproperty(J, obj, garbage);
	return tree;
}

js_Object *jsV_newobject(js_State *J, enum js_Class type, js_Object *prototype)
{
	js_Object *obj = js_malloc(J, sizeof *obj);
	memset(obj, 0, sizeof *obj);
	obj->gcmark = 0;
	obj->gcnext = J->gcobj;
	J->gcobj = obj;
	++J->gccounter;

	obj->type = type;
	obj->properties = &sentinel;
	obj->prototype = prototype;
	obj->extensible = 1;
	return obj;
}

js_Property *jsV_getownproperty(js_State *J, js_Object *obj, const char *name)
{
	return lookup(obj->properties, name);
}

js_Property *jsV_getpropertyx(js_State *J, js_Object *obj, const char *name, int *own)
{
	*own = 1;
	do {
		js_Property *ref = lookup(obj->properties, name);
		if (ref)
			return ref;
		obj = obj->prototype;
		*own = 0;
	} while (obj);
	return NULL;
}

js_Property *jsV_getproperty(js_State *J, js_Object *obj, const char *name)
{
	do {
		js_Property *ref = lookup(obj->properties, name);
		if (ref)
			return ref;
		obj = obj->prototype;
	} while (obj);
	return NULL;
}

static js_Property *jsV_getenumproperty(js_State *J, js_Object *obj, const char *name)
{
	do {
		js_Property *ref = lookup(obj->properties, name);
		if (ref && !(ref->atts & JS_DONTENUM))
			return ref;
		obj = obj->prototype;
	} while (obj);
	return NULL;
}

js_Property *jsV_setproperty(js_State *J, js_Object *obj, const char *name)
{
	js_Property *result;

	if (!obj->extensible) {
		result = lookup(obj->properties, name);
		if (J->strict && !result)
			js_typeerror(J, "object is non-extensible");
		return result;
	}

	obj->properties = insert(J, obj, obj->properties, name, &result);

	return result;
}

void jsV_delproperty(js_State *J, js_Object *obj, const char *name)
{
	obj->properties = deleteproperty(J, obj, obj->properties, name);
}

/* Flatten hierarchy of enumerable properties into an iterator object */

static js_Iterator *itnewnode(js_State *J, const char *name, js_Iterator *next) {
	int n = strlen(name) + 1;
	js_Iterator *node = js_malloc(J, offsetof(js_Iterator, name) + n);
	node->next = next;
	memcpy(node->name, name, n);
	return node;
}

static js_Iterator *itwalk(js_State *J, js_Iterator *iter, js_Property *prop, js_Object *seen)
{
	if (prop->right != &sentinel)
		iter = itwalk(J, iter, prop->right, seen);
	if (!(prop->atts & JS_DONTENUM)) {
		if (!seen || !jsV_getenumproperty(J, seen, prop->name)) {
			iter = itnewnode(J, prop->name, iter);
		}
	}
	if (prop->left != &sentinel)
		iter = itwalk(J, iter, prop->left, seen);
	return iter;
}

static js_Iterator *itflatten(js_State *J, js_Object *obj)
{
	js_Iterator *iter = NULL;
	if (obj->prototype)
		iter = itflatten(J, obj->prototype);
	if (obj->properties != &sentinel)
		iter = itwalk(J, iter, obj->properties, obj->prototype);
	return iter;
}

js_Object *jsV_newiterator(js_State *J, js_Object *obj, int own)
{
	js_Object *io = jsV_newobject(J, JS_CITERATOR, NULL);
	io->u.iter.target = obj;
	io->u.iter.i = 0;
	io->u.iter.n = 0;
	if (own) {
		io->u.iter.head = NULL;
		if (obj->properties != &sentinel)
			io->u.iter.head = itwalk(J, io->u.iter.head, obj->properties, NULL);
	} else {
		io->u.iter.head = itflatten(J, obj);
	}
	io->u.iter.current = io->u.iter.head;

	if (obj->type == JS_CSTRING)
		io->u.iter.n = obj->u.s.length;

	if (obj->type == JS_CARRAY && obj->u.a.simple)
		io->u.iter.n = obj->u.a.length;

	return io;
}

const char *jsV_nextiterator(js_State *J, js_Object *io)
{
	if (io->type != JS_CITERATOR)
		js_typeerror(J, "not an iterator");
	if (io->u.iter.i < io->u.iter.n) {
		js_itoa(J->scratch, io->u.iter.i);
		io->u.iter.i++;
		return J->scratch;
	}
	while (io->u.iter.current) {
		const char *name = io->u.iter.current->name;
		io->u.iter.current = io->u.iter.current->next;
		if (jsV_getproperty(J, io->u.iter.target, name))
			return name;
	}
	return NULL;
}

/* Walk all the properties and delete them one by one for arrays */

void jsV_resizearray(js_State *J, js_Object *obj, int newlen)
{
	char buf[32];
	const char *s;
	int k;
	assert(!obj->u.a.simple);
	if (newlen < obj->u.a.length) {
		if (obj->u.a.length > obj->count * 2) {
			js_Object *it = jsV_newiterator(J, obj, 1);
			while ((s = jsV_nextiterator(J, it))) {
				k = jsV_numbertointeger(jsV_stringtonumber(J, s));
				if (k >= newlen && !strcmp(s, jsV_numbertostring(J, buf, k)))
					jsV_delproperty(J, obj, s);
			}
		} else {
			for (k = newlen; k < obj->u.a.length; ++k) {
				jsV_delproperty(J, obj, js_itoa(buf, k));
			}
		}
	}
	obj->u.a.length = newlen;
}
