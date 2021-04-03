#ifndef R2_DIFF_H
#define R2_DIFF_H

#include <r_types.h>
#include <r_util.h>
#include <r_cons.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(r_diff);

#define Color_INSERT Color_BGREEN
#define Color_DELETE Color_BRED
#define Color_BGINSERT "\x1b[48;5;22m"
#define Color_BGDELETE "\x1b[48;5;52m"
#define Color_HLINSERT Color_BGINSERT Color_INSERT
#define Color_HLDELETE Color_BGDELETE Color_DELETE

typedef struct r_diff_op_t {
	/* file A */
	ut64 a_off;
	const ut8 *a_buf;
	ut32 a_len;

	/* file B */
	ut64 b_off;
	const ut8 *b_buf;
	ut32 b_len;
} RDiffOp;

//typedef struct r_diff_t RDiff;

typedef struct r_diff_t {
	ut64 off_a;
	ut64 off_b;
	int delta;
	void *user;
	bool verbose;
	int type;
	const char *diff_cmd;
	int (*callback)(struct r_diff_t *diff, void *user, RDiffOp *op);
} RDiff;

typedef enum {
	LEVEND, // array terminator
	LEVNOP, // no change
	LEVSUB, // substitution
	LEVADD, // add byte in bufb to bufa
	LEVDEL // delete byte from bufa
} RLevOp;

typedef struct r_lev_buf {
	void *buf;
	ut32 len;
} RLevBuf;
typedef bool (*RLevMatches)(RLevBuf *a, RLevBuf *b, ut32 ia, ut32 ib);

typedef int (*RDiffCallback) (RDiff *diff, void *user, RDiffOp *op);

typedef struct r_diffchar_t {
	const ut8 *align_a;
	const ut8 *align_b;
	size_t len_buf;
	size_t start_align;
} RDiffChar;

/* XXX: this api needs to be reviewed , constructor with offa+offb?? */
#ifdef R_API
R_API RDiff *r_diff_new(void);
R_API RDiff *r_diff_new_from(ut64 off_a, ut64 off_b);
R_API RDiff *r_diff_free(RDiff *d);

R_API int r_diff_buffers(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb);
R_API int r_diff_buffers_static(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb);
R_API int r_diff_buffers_radiff(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb);
R_API int r_diff_buffers_delta(RDiff *diff, const ut8 *sa, int la, const ut8 *sb, int lb);
R_API int r_diff_buffers(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb);
R_API char *r_diff_buffers_to_string(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb);
R_API int r_diff_set_callback(RDiff *d, RDiffCallback callback, void *user);
R_API bool r_diff_buffers_distance(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity);
R_API bool r_diff_buffers_distance_myers(RDiff *diff, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity);
R_API bool r_diff_buffers_distance_levenshtein(RDiff *d, const ut8 *a, ut32 la, const ut8 *b, ut32 lb, ut32 *distance, double *similarity);
R_API char *r_diff_buffers_unified(RDiff *d, const ut8 *a, int la, const ut8 *b, int lb);
/* static method !??! */
R_API int r_diff_lines(const char *file1, const char *sa, int la, const char *file2, const char *sb, int lb);
R_API int r_diff_set_delta(RDiff *d, int delta);
R_API int r_diff_gdiff(const char *file1, const char *file2, int rad, int va);

R_API RDiffChar *r_diffchar_new(const ut8 *a, const ut8 *b);
R_API void r_diffchar_print(RDiffChar *diffchar);
R_API void r_diffchar_free(RDiffChar *diffchar);
R_API st32 r_diff_levenshtein_path(RLevBuf *bufa, RLevBuf *bufb, ut32 maxdst, RLevMatches levdiff, RLevOp **chgs);
#endif

#ifdef __cplusplus
}
#endif

#endif
