include ../../../global.mk
SDB=$(LTOP)/db/sdb/src/sdb

all: dospart.sdb

%.sdb:% ${SDB}
	@echo "  SDB $<"
	@-${SDB} $<.sdb = < $<

clean:
	rm -f dospart.sdb

${SDB}:
	cp -rf $(LTOP)/db/sdb/src $(LTOP)/db/sdb/src-native
	#cd $(LTOP)/db/sdb/src-native && ${MAKE} -j ${MAKE_JOBS} ARCH=xxx CC=gcc clean sdb
	cd $(LTOP)/db/sdb/src-native && ${MAKE} -j 1 ARCH=xxx CC=gcc clean sdb
	cp -f $(LTOP)/db/sdb/src-native/sdb $(SDB)
	rm -rf $(LTOP)/db/sdb/src-native

.PHONY: all clean
