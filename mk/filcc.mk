ifeq (${_INCLUDE_MK_FILCC_},)
_INCLUDE_MK_FILCC_=1
include $(dir $(lastword $(MAKEFILE_LIST)))clang.mk
CFLAGS:=$(filter-out -MD,$(CFLAGS))
CC?=filcc
AR?=ar
RANLIB?=ranlib
LD?=ld
endif
