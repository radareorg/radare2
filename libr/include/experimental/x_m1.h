#ifndef X_M1_H
#define X_M1_H

#include <r_bin.h>

#ifdef __cplusplus
extern "C" {
#endif

//R_API void r_bin_sorted_section_free (void  /*RBinSortedSection*/ *data);
//R_API int r_bin_sorted_section_vaddr_cmp (const RBinSortedSection *a, const RBinSortedSection *b);
//R_API int r_bin_sorted_section_paddr_cmp (const RBinSortedSection *a, const RBinSortedSection *b);
//R_API int r_bin_sorted_section_contains_addr (const RBinSortedSection *a, ut64 off, int va);
R_API ut64 r_bin_section_get_from_addr (RBinObject *o, RBinSection *s, int va);
R_API ut64 r_bin_section_get_to_addr (RBinObject *o, RBinSection *s, int va);

R_API void x_m1_init (RBinObject *o);
R_API void x_m1_fini (RBinObject *o);

R_API RBinSection *r_bin_get_section_at (RBinObject *o, ut64 off, int va);

#ifdef __cplusplus
}
#endif

#endif // X_M1_H
