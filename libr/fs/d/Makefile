include ../../../global.mk
SDB=$(STOP)/sdb/sdb

all: dospart.sdb

%.sdb:% ${SDB}
	@echo "  SDB $<"
	@-${SDB} $<.sdb = < $<

clean:
	rm -f dospart.sdb

${SDB}:
	cp -rf $(STOP)/sdb/src $(STOP)/sdb/src-native
	cd $(STOP)/sdb/src-native && ${MAKE} -j 1 ARCH=xxx CC=gcc clean sdb
	cp -f $(STOP)/sdb/src-native/sdb $(SDB)
	rm -rf $(STOP)/sdb/src-native

.PHONY: all clean
