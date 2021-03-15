ifeq ($(USE_CAPSTONE),1)
CS_CFLAGS=${CAPSTONE_CFLAGS}
CS_LDFLAGS=${CAPSTONE_LDFLAGS}
else
CS_CFLAGS=-I../../shlr/capstone/include
CS_CFLAGS+=-I../../../shlr/capstone/include
CS_CFLAGS+=-I../../shlr/capstone/include/capstone
CS_CFLAGS+=-I../../../shlr/capstone/include/capstone
CS_LDFLAGS=$(SHLR)/capstone/libcapstone.a
endif

ifeq ($(CS_CFLAGS_INCLUDED),)
CFLAGS+=$(CS_CFLAGS)
CS_CFLAGS_INCLUDED=Yes
endif
