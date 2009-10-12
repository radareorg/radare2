/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_search.h"

R_API int r_search_init(struct r_search_t *s, int mode)
{
	memset(s,'\0', sizeof(struct r_search_t));
	if (!r_search_set_mode(s, mode))
		return R_FALSE;
	s->mode = mode;
	s->user = NULL;
	s->callback = NULL;
	s->pattern_size = 0;
	s->string_max = 255;
	s->string_min = 3;
	INIT_LIST_HEAD(&(s->kws));
	INIT_LIST_HEAD(&(s->hits));
	INIT_LIST_HEAD(&(s->hits));
	return R_TRUE;
}

R_API int r_search_set_string_limits(struct r_search_t *s, ut32 min, ut32 max)
{
	if (max < min)
		return R_FALSE;
	s->string_min = min;
	s->string_max = max;
	return R_TRUE;
}

R_API int r_search_set_mode(struct r_search_t *s, int mode)
{
	int ret = R_FALSE;
	switch(mode) {
	case R_SEARCH_KEYWORD:
	case R_SEARCH_REGEXP:
	case R_SEARCH_PATTERN:
	case R_SEARCH_STRING:
	case R_SEARCH_XREFS:
	case R_SEARCH_AES:
		s->mode = mode;
		ret = R_TRUE;
	}
	return ret;
}

R_API struct r_search_t *r_search_new(int mode)
{
	struct r_search_t *s = MALLOC_STRUCT(struct r_search_t);
	if (r_search_init(s, mode) == -1) {
		free(s);
		s = NULL;
	}
	return s;
}

R_API void r_search_deinit(struct r_search_t *s)
{
	// TODO: free linked lists and so on
}

R_API struct r_search_t *r_search_free(struct r_search_t *s)
{
	r_search_deinit(s);
	free(s);
	return NULL;
}

/* control */
R_API int r_search_begin(struct r_search_t *s)
{
	struct list_head *pos;

	list_for_each_prev(pos, &s->kws) {
		struct r_search_kw_t *kw = list_entry(pos, struct r_search_kw_t, list);
		kw->count = 0;
		kw->idx = 0;
	}

#if 0
	/* TODO: compile regexpes */
	switch(s->mode) {
	case R_SEARCH_REGEXP:
		break;
	}
#endif

	return 1;
}

// TODO: move into a plugin */
R_API int r_search_mybinparse_update(struct r_search_t *s, ut64 from, const ut8 *buf, int len)
{
	struct list_head *pos;
	int i, count = 0;

	for(i=0;i<len;i++) {
		list_for_each_prev(pos, &s->kws) {
			struct r_search_kw_t *kw = list_entry(pos, struct r_search_kw_t, list);
			ut8 ch = kw->bin_keyword[kw->idx];
			ut8 ch2 = buf[i];
			if (kw->binmask_length != 0 && kw->idx < kw->binmask_length) {
				ch &= kw->bin_binmask[kw->idx];
				ch2 &= kw->bin_binmask[kw->idx];
			}
			if (ch == ch2) {
				kw->idx++;
				if (kw->idx == kw->keyword_length) {
					if (s->callback)
						s->callback(kw, s->user, (ut64)from+i-kw->keyword_length+1);
					else printf("hit%d_%d 0x%08llx ; %s\n",
						count, kw->count, (ut64)from+i+1, buf+i-kw->keyword_length+1);
					kw->idx = 0;
					kw->count++;
				}
			} else kw->idx = 0;
			count++;
		}
		count = 0;
	}
	return count;
}

R_API int r_search_set_pattern_size(struct r_search_t *s, int size)
{
	s->pattern_size = size;
	return 0;
}

R_API int r_search_set_callback(struct r_search_t *s, int (*callback)(struct r_search_kw_t *, void *, ut64), void *user)
{
	s->callback = callback;
	s->user = user;
	return 0;
}

/* TODO: initialize update callback in _init */
R_API int r_search_update(struct r_search_t *s, ut64 *from, const ut8 *buf, long len)
{
	int ret = 0;
	switch(s->mode) {
	case R_SEARCH_KEYWORD:
		ret += r_search_mybinparse_update(s, *from, buf, len);
		break;
	case R_SEARCH_XREFS:
		r_search_xrefs_update(s, *from, buf, len);
		break;
	case R_SEARCH_REGEXP:
		ret += r_search_regexp_update(s, *from, buf, len);
		break;
	case R_SEARCH_AES:
		ret += r_search_aes_update(s, *from, buf, len);
		*from -= R_SEARCH_AES_BOX_SIZE;
		break;
	case R_SEARCH_STRING:
		ret += r_search_strings_update(s, *from, buf, len, 0);
		break;
	case R_SEARCH_PATTERN:
		//ret += r_search_pattern_update(buf, s->pattern_size
		break;
	}
	return ret;
}

R_API int r_search_update_i(struct r_search_t *s, ut64 from, const ut8 *buf, long len)
{
	return r_search_update(s, &from, buf, len);
}

/* --- keywords --- */

/* string */
R_API int r_search_kw_add(struct r_search_t *s, const char *kw, const char *bm)
{
	struct r_search_kw_t *k = MALLOC_STRUCT(struct r_search_kw_t);
	int kwlen = strlen(kw)+1;
	if (k == NULL)
		return R_FALSE;
	if (bm == NULL) bm = "";
	memcpy(k->keyword, kw, kwlen);
	memcpy(k->bin_keyword, kw, kwlen);
	k->keyword_length = strlen(kw);
	if (k->binmask_length == -1)
		k->binmask_length = strlen(bm);
	if (bm) {
		memcpy(k->binmask, bm, k->binmask_length);
		k->binmask_length = r_hex_str2bin(bm, k->bin_binmask);
	} else k->binmask[0] = k->binmask_length = 0;
	list_add(&(k->list), &(s->kws));
	k->kwidx = s->n_kws++;
	return R_TRUE;
}

/* hexpair string */
R_API int r_search_kw_add_hex(struct r_search_t *s, const char *kw, const char *bm)
{
	struct r_search_kw_t *k = MALLOC_STRUCT(struct r_search_kw_t);
	if (k == NULL) // is necessary to assert everywhere??
		return R_FALSE;
	strncpy(k->keyword, kw, sizeof(k->keyword));
	k->keyword_length = r_hex_str2bin(kw, k->bin_keyword);
	if (bm) {
		strncpy(k->binmask, bm, sizeof(k->binmask));
		k->binmask_length = r_hex_str2bin(bm, k->bin_binmask);
	} else k->binmask[0] = k->binmask_length = 0;
	list_add(&(k->list), &(s->kws));
	k->kwidx = s->n_kws++;
	return R_TRUE;
}

/* raw bin */
R_API int r_search_kw_add_bin(struct r_search_t *s, const ut8 *kw, int kw_len, const ut8 *bm, int bm_len)
{
	struct r_search_kw_t *k = MALLOC_STRUCT(struct r_search_kw_t);
	if (kw == NULL)
		return R_FALSE;
	memcpy(k->bin_keyword, kw, kw_len);
	k->keyword_length = kw_len;
	r_hex_bin2str(kw, kw_len, k->keyword);
	if (bm) memcpy(k->bin_binmask, bm, bm_len);
	if (bm) r_hex_bin2str(bm, bm_len, k->binmask);
	else k->binmask_length = 0;
	list_add(&(k->list), &(s->kws));
	k->kwidx = s->n_kws++;
	return R_TRUE;
}

/* show keywords */
R_API struct r_search_kw_t *r_search_kw_list(struct r_search_t *s)
{
	struct list_head *pos;
	list_for_each_prev(pos, &s->kws) {
		struct r_search_kw_t *kw = list_entry(pos, struct r_search_kw_t, list);
		printf("%s %s\n", kw->keyword, kw->binmask);
	}
	return NULL;
}

R_API int r_search_reset(struct r_search_t *s)
{
	// TODO
	return R_TRUE;
}

R_API int r_search_kw_reset(struct r_search_t *s)
{
	// TODO
	return R_TRUE;
}
