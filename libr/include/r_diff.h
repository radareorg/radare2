#ifndef R2_DIFF_H
#define R2_DIFF_H

#include <r_types.h>
#include <r_util.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_diff);

typedef struct r_diff_op_t {
	/* file A */
	ut64 a_off;
	const ut8 *a_buf;
	int a_len;

	/* file B */
	ut64 b_off;
	const ut8 *b_buf;
	int b_len;
} RDiffOp;

//typedef struct r_diff_t RDiff;

typedef struct r_diff_t {
	ut64 off_a;
	ut64 off_b;
	int delta;
	void *user;
	int (*callback)(struct r_diff_t *diff, void *user, RDiffOp *op);
} RDiff;

typedef int (*RDiffCallback)(RDiff *diff, void *user, RDiffOp *op);

/* XXX: this api needs to be reviewed , constructor with offa+offb?? */
#ifdef R_API
R_API RDiff *r_diff_new(ut64 off_a, ut64 off_b);
R_API RDiff *r_diff_free(RDiff *d);

R_API int r_diff_buffers(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb);
R_API int r_diff_buffers_static(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb);
R_API int r_diff_buffers_radiff(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb);
R_API int r_diff_buffers_delta(RDiff *diff, const ut8 *sa, int la, const ut8 *sb, int lb);
R_API int r_diff_buffers(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb);
R_API int r_diff_set_callback(RDiff *d, RDiffCallback callback, void *user);
R_API int r_diff_buffers_distance(RDiff *d,
	const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance,
	double *similarity);
/* static method !??! */
R_API int r_diff_lines(const char *file1, const char *sa, int la, const char *file2, const char *sb, int lb);
R_API int r_diff_set_delta(RDiff *d, int delta);
R_API int r_diff_gdiff(const char *file1, const char *file2, int rad, int va);
#endif

#ifdef __cplusplus
}
#endif

#endif
