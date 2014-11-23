#LDFLAGS+=${STOP}/zip/librz.a
#LINK+=${STOP}/zip/zip/*.o
#LINK+=${STOP}/zip/zlib/*.o
ifeq ($(USE_LIB_ZIP),1)
LINK+=$(LIBZIP)
else
LINK+=../../shlr/zip/librz.a
endif
