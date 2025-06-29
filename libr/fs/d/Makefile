include ../../../global.mk

# this bin should be created by make -C shlr/Makefile sdb/sdb
SDB=$(STOP)/../subprojects/sdb/sdb
DBS=dospart.sdb

all: $(DBS)

%.sdb: ${SDB}
	$(SDB) -r .

clean:
	rm -f *.sdb *.c

$(SDB):
	@echo "Cannot find sdb/sdb"
	@false

.PHONY: all clean
