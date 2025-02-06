ifeq ($(WANT_CAPSTONE),1)
  ifeq ($(USE_CAPSTONE),1)
    CS_CFLAGS=${CAPSTONE_CFLAGS}
    CS_LDFLAGS=${CAPSTONE_LDFLAGS}
  else
    CS_CFLAGS=-I$(CS_ROOT)/include
    CS_LDFLAGS=$(CS_ROOT)/libcapstone.a
  endif

  ifeq ($(CS_CFLAGS_INCLUDED),)
    CFLAGS+=$(CS_CFLAGS)
    CS_CFLAGS_INCLUDED=Yes
  endif
else
  CS_CFLAGS=
endif
