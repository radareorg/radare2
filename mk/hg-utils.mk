# radare :: pancake // nopcode.org
# Makefile helpers for mercurial

hg-miss:
	@-hg st . | grep -e vala$$ -e mk$$ | grep ^? | grep -v config-user || true
	@-hg st . | grep -e \\.c$$ | grep -v vapi | grep ^? || true
	@-hg st . | grep -e \\.h$$ | grep -v vapi | grep ^? | grep -v r_userconf || true

FILES?=
hg-locdiff:
	@A=`hg diff ${FILES} | grep -v '+++' | grep ^+ |wc -l` ; \
	B=`hg diff ${FILES} | grep -v -- '---' | grep ^- |wc -l` ; \
	echo $$((A-B))

hg-help:
	@echo "hg-utils.mk mercurial utilities"
	@echo "-----------.-------------------"
	@echo "hg-miss    | list interesting missing files"
	@echo "hg-locdiff | count the difference of LOCs for current commit or FILES"
	@echo "           $$ hg-locdiff \"FILES=Makefile foo.c\""
