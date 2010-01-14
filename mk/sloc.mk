sloc:
	@if [ -n "$${SLOCDIR}" ]; then cd $$SLOCDIR ; fi ; \
	total=0 ; \
	for a in `find * -iname '*.c'`; do \
	lines=$$(sloccount $$a |grep ansic= | cut -d ' ' -f 1) ; \
	printf "$$lines\t$$a\n" ; \
	total=$$(($$total+$$lines)) ; \
	done ; \
	printf "$$total\tTOTAL\n"

.PHONY: sloc
