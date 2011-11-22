SDB=../../db/sdb/src/sdb

all: dospart.sdb

%.sdb:%
	@echo "  SDB $<"
	@-${SDB} $<.sdb = < $<

clean:
	rm -f dospart.sdb
