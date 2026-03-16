ifeq ($(WANT_CAPSTONE),1)
  ifeq ($(CS_CFLAGS_INCLUDED),)
    CFLAGS+=$(CS_CFLAGS)
    CS_CFLAGS_INCLUDED=Yes
  endif
endif
