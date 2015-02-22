ifeq ($(USE_LIB_ZIP),1)
LINK+=$(LIBZIP)
else
LINK+=$(STOP)/zip/librz.a
CFLAGS+=-I$(SHLR)/zip/include
endif
