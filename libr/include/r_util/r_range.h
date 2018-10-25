#ifndef R_RANGE_H
#define R_RANGE_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct r_range_tiny_t {
	int pairs;
	int count;
	ut64 *ranges;
} RRangeTiny;

R_API RRangeTiny *r_tinyrange_new(void);
R_API void r_tinyrange_init(RRangeTiny *bbr);
R_API void r_tinyrange_fini(RRangeTiny *bbr);
R_API bool r_tinyrange_in(RRangeTiny *bbr, ut64 at);
R_API bool r_tinyrange_add(RRangeTiny *bbr, ut64 from, ut64 to);
R_API void r_tinyrange_free(RRangeTiny *bbr);

/* range.c */

typedef struct r_range_item_t {
	ut64 fr;
	ut64 to;
	ut8 *data;
	int datalen;
} RRangeItem;

typedef struct r_range_t {
	int count;
	int changed;
	RList *ranges;
} RRange;

R_API RRange *r_range_new(void);
R_API RRange *r_range_new_from_string(const char *string);
R_API RRange *r_range_free(RRange *r);
R_API RRangeItem *r_range_item_get(RRange *r, ut64 addr);
R_API ut64 r_range_size(RRange *r);
R_API int r_range_add_from_string(RRange *rgs, const char *string);
R_API RRangeItem *r_range_add(RRange *rgs, ut64 from, ut64 to, int rw);
R_API int r_range_sub(RRange *rgs, ut64 from, ut64 to);
R_API void r_range_merge(RRange *rgs, RRange *r);
R_API int r_range_contains(RRange *rgs, ut64 addr);
R_API int r_range_sort(RRange *rgs);
R_API void r_range_percent(RRange *rgs);
R_API int r_range_list(RRange *rgs, int rad);
R_API int r_range_get_n(RRange *rgs, int n, ut64 *from, ut64 *to);
R_API RRange *r_range_inverse(RRange *rgs, ut64 from, ut64 to, int flags);
R_API int r_range_overlap(ut64 a0, ut64 a1, ut64 b0, ut64 b1, int *d);

#ifdef __cplusplus
}
#endif

#endif //  R_RANGE_H
