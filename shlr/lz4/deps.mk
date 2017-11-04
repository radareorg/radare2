ifeq ($(USE_LIB_LZ4),1)
LINK+=$(LIBLZ4)
else
LINK+=$(SHLR)/lz4/liblz4.$(EXT_AR)
endif
