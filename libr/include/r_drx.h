#ifndef R2_DRX_H
#define R2_DRX_H

#ifdef __cplusplus
extern "C" {
#endif

enum {
  DRX_API_LIST = 0,
  DRX_API_GET_BP = 1,
  DRX_API_SET_BP = 2,
  DRX_API_REMOVE_BP = 3,
};

#if __i386__ || __x86_64__
#define NUM_DRX_REGISTERS 8
#else
#define NUM_DRX_REGISTERS 0
#endif

#ifdef __cplusplus
}
#endif

#endif
