ifeq ($(WITHNONPIC),1)
LDFLAGS+=$(LIBR)/db/sdb/src/libsdb.a
else
LDFLAGS+=-L$(LIBR)/db -lr_db
endif
