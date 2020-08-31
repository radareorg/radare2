#ifndef R2_TIME_H
#define R2_TIME_H

#define R_TIME_ENABLED 0

#if R_TIME_ENABLED
#define R_TIME_BEGIN ut64 __now__ = r_sys_now()
#define R_TIME_END eprintf ("%s %"PFMT64d"\n", __FUNCTION__, r_sys_now() - __now__)
#else
#define R_TIME_BEGIN do{}while(0)
#define R_TIME_END do{}while(0)
#endif

#endif
