ifeq ($(USE_CAPSTONE),1)
CS_CFLAGS=${CAPSTONE_CFLAGS}
CS_LDFLAGS=${CAPSTONE_LDFLAGS}
else
CS_CFLAGS=-I../../shlr/capstone/include
CS_CFLAGS+=-I../../../shlr/capstone/include
CS_LDFLAGS=$(SHLR)/capstone/libcapstone.a
SHARED_OBJ+=${CS_LDFLAGS}
endif

ifeq ($(CS_CFLAGS_INCLUDED),)
CFLAGS+=$(CS_CFLAGS)
CS_CFLAGS_INCLUDED=Yes
endif
