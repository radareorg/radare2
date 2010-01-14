sloc:
	@if [ -n "$${SLOCDIR}" ]; then cd $$SLOCDIR ; fi ; \
	for a in `find * -iname *.c`; do \
	printf "$$a \t" ; \
	sloccount $$a |grep ansic= | cut -d ' ' -f 1 ; \
	done

.PHONY: sloc
