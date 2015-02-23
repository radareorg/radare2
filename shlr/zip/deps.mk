#ifeq ($(SHLR),)
#SHLR=../../shlr
#endif

ifeq ($(USE_LIB_ZIP),1)
LINK+=$(LIBZIP)
else
LINK+=$(SHLR)/zip/librz.a
CFLAGS+=-I$(SHLR)/zip/include
endif
