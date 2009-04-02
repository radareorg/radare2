/* radare - LGPL - Copyright 2006-2009 pancake<nopcode.org> */

#include "r_config.h"
#include "r_util.h" // r_str_hash, r_str_clean, ...

struct r_config_node_t* r_config_node_new(const char *name, const char *value)
{
	struct r_config_node_t *node = 
		(struct r_config_node_t *)
			malloc(sizeof(struct r_config_node_t));
	INIT_LIST_HEAD(&(node->list));
	node->name = strdup(name);
	node->hash = r_str_hash(name);
	node->value = value?strdup(value):strdup("");
	node->flags = CN_RW | CN_STR;
	node->i_value = 0;
	node->callback = NULL;
	return node;
}

void r_config_list(struct r_config_t *cfg, const char *str, int rad)
{
	struct list_head *i;
	int len = 0;

	if (!strnull(str)) {
		str = r_str_clean(str);
		len = strlen(str);
	}

	list_for_each(i, &(cfg->nodes)) {
		struct r_config_node_t *bt = list_entry(i, struct r_config_node_t, list);
		if (str) {
			if (strncmp(str, bt->name, len) == 0) {
				if (rad) cfg->printf("f ");
				cfg->printf("%s = %s\n", bt->name, bt->value);
			}
		} else {
			if (rad) cfg->printf("f ");
			cfg->printf("%s = %s\n", bt->name, bt->value);
		}
	}
}

struct r_config_node_t *r_config_node_get(struct r_config_t *cfg, const char *name)
{
	struct list_head *i;
	int hash;
	if (strnull(name))
		return NULL;
	hash = r_str_hash(name);
	list_for_each_prev(i, &(cfg->nodes)) {
		struct r_config_node_t *bt = list_entry(i, struct r_config_node_t, list);
		if (bt->hash == hash)
			return bt;
	}
	return NULL;
}

const char *r_config_get(struct r_config_t *cfg, const char *name)
{
	struct r_config_node_t *node =
		r_config_node_get(cfg, name);
	if (node) {
		cfg->last_notfound = 0;
		if (node->flags & CN_BOOL)
			return (const char *)
				(((!strcmp("true", node->value))
				  || (!strcmp("1", node->value)))?(const char *)1:NULL);
		return node->value;
	}
	cfg->last_notfound = 1;
	return NULL;
}

u64 r_config_get_i(struct r_config_t *cfg, const char *name)
{
	struct r_config_node_t *node =
		r_config_node_get(cfg, name);
	if (node) {
		if (node->i_value != 0)
			return node->i_value;
		return (u64)r_num_math(NULL, node->value);
	}
	return (u64)0LL;
}

struct r_config_node_t *r_config_set_cb(struct r_config_t *cfg, const char *name, const char *value, int (*callback)(void *user, void *data))
{
	struct r_config_node_t *node;
	node = r_config_set(cfg, name, value);
	node->callback = callback;
	if (node->callback)
		node->callback(cfg->user, node);
	return node;
}

struct r_config_node_t *r_config_set(struct r_config_t *cfg, const char *name, const char *value)
{
	struct r_config_node_t *node;

	if (name[0] == '\0')
		return NULL;

	node = r_config_node_get(cfg, name);

	// TODO: store old value somewhere..
	if (node) {
		if (node->flags & CN_RO) {
			eprintf("(read only)\n");
			return node;
		}
		free(node->value);
		if (node->flags & CN_BOOL) {
			int b = (!strcmp(value,"true")||!strcmp(value,"1"));
			node->i_value = (u64)(b==0)?0:1;
			node->value = strdup(b?"true":"false");
		} else {
			if (value == NULL) {
				node->value = strdup("");
				node->i_value = 0;
			} else {
				node->value = strdup(value);
				if (strchr(value, '/'))
					node->i_value = r_num_get(NULL, value);
				else  node->i_value = r_num_math(NULL, value);
				node->flags |= CN_INT;
			}
		}
	} else {
		if (cfg->lock) {
			fprintf(stderr, "config is locked: cannot create '%s'\n", name);
		} else {
			node = r_config_node_new(name, value);
			if (value && (!strcmp(value,"true")||!strcmp(value,"false"))) {
				node->flags|=CN_BOOL;
				node->i_value = (!strcmp(value,"true"))?1:0;
			}
			list_add_tail(&(node->list), &(cfg->nodes));
			cfg->n_nodes++;
		}
	}

	if (node && node->callback)
		node->callback(cfg->user, node);
	return node;
}

int r_config_rm(struct r_config_t *cfg, const char *name)
{
	struct r_config_node_t *node =
		r_config_node_get(cfg, name);
	if (node) {
		list_del(&(node->list));
		cfg->n_nodes--;
		return 1;
	}
	return 0;
}

struct r_config_node_t *r_config_set_i(struct r_config_t *cfg, const char *name, const u64 i)
{
	char buf[128];
	struct r_config_node_t *node =
		r_config_node_get(cfg, name);

	if (node) {
		if (node->flags & CN_RO)
			return NULL;
		free(node->value);
		if (node->flags & CN_BOOL) {
			node->value = strdup(i?"true":"false");
		} else {
			sprintf(buf, "%lld", i); //0x%08lx", i);
			node->value = strdup(buf);
		}
		node->flags = CN_RW | CN_INT;
		node->i_value = i;
	} else {
		if (cfg->lock) {
			eprintf("(locked: no new keys can be created)");
		} else {
			sprintf(buf, "%d", (unsigned int)i);//OFF_FMTd, (u64) i);
			node = r_config_node_new(name, buf);
			node->flags = CN_RW | CN_OFFT;
			node->i_value = i;
			list_add_tail(&(node->list), &(cfg->nodes));
			cfg->n_nodes++;
		}
	}

	if (node && node->callback)
		node->callback(cfg->user, node);

	return node;
}

int r_config_eval(struct r_config_t *cfg, const char *str)
{
	char *ptr,*a,*b;
	char *name;
	int len;

	if (str == NULL)
		return 0;

	len = strlen(str)+1;
	name = alloca(len);
	memcpy(name, str, len);
	str = r_str_clean(name);

	if (str == NULL)
		return 0;

	if (str[0]=='\0'||!strcmp(str, "help")) {
		r_config_list(cfg, NULL, 0);
		return 0;
	}

	if (str[0]=='-') {
		r_config_rm(cfg, str+1);
		return 0;
	}

	ptr = strchr(str, '=');
	if (ptr) {
		/* set */
		ptr[0]='\0';
		a = r_str_clean(name);
		b = r_str_clean(ptr+1);
		r_config_set(cfg, a, b);
	} else {
		char *foo = r_str_clean(name);
		if (foo[strlen(foo)-1]=='.') {
			/* list */
			r_config_list(cfg, name, 0);
			return 0;
		} else {
			/* get */
			const char * str = r_config_get(cfg, foo);
			if (cfg->last_notfound)
				r_config_list(cfg, name, 0);
			else cfg->printf("%s\n", (((int)str)==1)?"true":(str==0)?"false":str);
		}
	}
	return 1;
}

void r_config_lock(struct r_config_t *cfg, int l)
{
	cfg->lock = l;
}

int r_config_init(struct r_config_t *cfg, void *user)
{
	cfg->user = user;
	cfg->n_nodes = 0;
	cfg->lock = 0;
	cfg->printf = printf;
	INIT_LIST_HEAD(&(cfg->nodes));
	return 0;
}

struct r_config_t *r_config_new(void *user)
{
	struct r_config_t *cfg = (struct r_config_t *)
		malloc(sizeof(struct r_config_t));
	r_config_init(cfg, user);
	return cfg;
}

int r_config_free(struct r_config_t *cfg)
{
	// TODO: Free node list
	free(cfg);
	return 0;
}

void r_config_visual_hit_i(struct r_config_t *cfg, const char *name, int delta)
{
	struct r_config_node_t *node =
		r_config_node_get(cfg, name);
	if (node && (node->flags & CN_INT || node->flags & CN_OFFT))
		r_config_set_i(cfg, name, r_config_get_i(cfg, name)+delta);
}
