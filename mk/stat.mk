stat-todo:
	@printf "XXX\tTODO\tName\n"
	@for a in libr/* ; do \
		if [ -d "$$a" ]; then \
			xxx=`grep -e XXX $$a/*.c $$a/p/*.c $$a/t/*.c 2>/dev/null | wc -l` ; \
			todo=`grep -e TODO $$a/*.c $$a/p/*.c $$a/t/*.c 2>/dev/null | wc -l` ; \
			printf "$$xxx\t$$todo\t$$a\n" ; \
		fi ; \
	done

stat-make:
	make 2>&1 | perl mk/stat-make.pl
