LINK+=$(STOP)/winkd/libr_winkd.${EXT_AR}
LDFLAGS+=-lr_crypto -lr_hash
include $(LIBR)/socket/deps.mk
