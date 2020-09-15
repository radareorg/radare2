
ifeq ($(USE_CAPSTONE),1)
# use system capstone
CS_CFLAGS=${CAPSTONE_CFLAGS}
CS_LDFLAGS=${CAPSTONE_LDFLAGS}
else
# use capstone from shlr/capstone
CS_CFLAGS=-I${SHLR}/capstone/include
CS_CFLAGS=-I${SHLR}/capstone/include/capstone
CS_LDFLAGS=$(SHLR)/capstone/libcapstone.a
#SHARED_OBJ+=${CS_LDFLAGS}
endif

ifeq ($(CS_CFLAGS_INCLUDED),)
CFLAGS+=$(CS_CFLAGS)
CS_CFLAGS_INCLUDED=Yes
endif
