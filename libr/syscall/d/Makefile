FILES=netbsd-x86-32

all:
	@for a in ${FILES} ; do \
		echo " SDB  $$a.sdb" ; \
		sh gen.sh < $$a | sdb $$a.sdb = ; \
	done

clean:
	rm -f *.sdb
