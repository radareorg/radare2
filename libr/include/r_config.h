#ifndef _INCLUDE_R_CONFIG_H_
#define _INCLUDE_R_CONFIG_H_

#include "r_types.h"
#include "r_util.h"
#include "list.h"

#define CN_BOOL  0x000001
#define CN_INT   0x000002
#define CN_OFFT  0x000004
#define CN_STR   0x000008
#define CN_RO    0x000010
#define CN_RW    0x000020

struct r_config_node_t {
	char *name;
	int hash;
	int flags;
	char *value;
	u64 i_value;
	u64 *cb_ptr_q;
	int *cb_ptr_i;
	char **cb_ptr_s;
	int (*callback)(void *user, void *data);
	struct list_head list;
};

struct r_config_t {
	int lock;
	int last_notfound;
	int n_nodes;
	void *user;
	void (*printf)(const char *str, ...);
	struct list_head nodes;
};

#define O struct r_config_t *obj

struct r_config_t *r_config_new(void *user);
int r_config_free(struct r_config_t *cfg);
int r_config_init(struct r_config_t *core, void *user);
void r_config_lock(O, int l);
int r_config_eval(O, const char *str);
struct r_config_node_t *r_config_set_i(O, const char *name, const u64 i);
struct r_config_node_t *r_config_set_cb(struct r_config_t *cfg, const char *name, const char *value, int (*callback)(void *user, void *data));
int r_config_rm(O, const char *name);
struct r_config_node_t *r_config_set(O, const char *name, const char *value);
u64 r_config_get_i(O, const char *name);
const char *r_config_get(O, const char *name);
void r_config_list(O, const char *str, int rad);
struct r_config_node_t *r_config_node_get(O, const char *name);
struct r_config_node_t *r_config_node_new(const char *name, const char *value);

#endif
