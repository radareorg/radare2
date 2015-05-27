include ../../../global.mk

# this bin should be created by make -C shlr/Makefile sdb/sdb
SDB=$(STOP)/sdb/sdb
DBS=dospart.sdb

all: $(DBS)

%.sdb:% ${SDB}
	@echo "  SDB $<"
	@-${SDB} $<.sdb = < $<
	@test -f $<.sdb

clean:
	rm -f *.sdb

$(SDB):
	@echo "Cannot find sdb/sdb"
	@false

#	cp -rf $(STOP)/sdb/src $(STOP)/sdb/src-native
#	cd $(STOP)/sdb/src-native && ${MAKE} -j 1 ARCH=xxx CC=gcc clean sdb
#	cp -f $(STOP)/sdb/src-native/sdb $(SDB)
#	rm -rf $(STOP)/sdb/src-native

.PHONY: all clean
