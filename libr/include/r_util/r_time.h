#ifndef R2_TIME_H
#define R2_TIME_H

#define R_TIME_BEGIN ut64 __now__ = r_sys_now()
#define R_TIME_END eprintf ("%s %"PFMT64d"\n", __FUNCTION__, r_sys_now() - __now__)

#endif
