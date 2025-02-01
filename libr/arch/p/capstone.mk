ifeq ($(USE_CSNEXT),1)
  CS_ROOT=../../subprojects/capstone-next
else
ifeq ($(USE_CS4),1)
  CS_ROOT=../../subprojects/capstone-v4
else
  CS_ROOT=../../subprojects/capstone-v5
endif
endif

ifeq ($(WANT_CAPSTONE),1)
  ifeq ($(USE_CAPSTONE),1)
    CS_CFLAGS=${CAPSTONE_CFLAGS}
    CS_LDFLAGS=${CAPSTONE_LDFLAGS}
  else
    #CS_CFLAGS=-I../../shlr/capstone/include
    CS_CFLAGS=-I$(CS_ROOT)/include
    #CS_CFLAGS+=-I../$(CS_ROOT)/include
    #CS_CFLAGS+=-I../../shlr/capstone/include/capstone
    #CS_CFLAGS+=-I$(CS_ROOT)/include/capstone
    #CS_CFLAGS+=-I$(CS_ROOT)/include/capstone
    CS_LDFLAGS=$(CS_ROOT)/libcapstone.a
  endif

  $(info [cs_flags] - $(CS_CFLAGS))

  ifeq ($(CS_CFLAGS_INCLUDED),)
    CFLAGS+=$(CS_CFLAGS)
    CS_CFLAGS_INCLUDED=Yes
  endif
else
  CS_CFLAGS=
endif
