FILES=x86 arm ppc
SDB=../../db/sdb/src/sdb

all:
	for a in ${FILES} ; do ${SDB} $${a}.sdb = < $$a ; done

clean:
	rm -f *.sdb
