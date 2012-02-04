# radare :: pancake // nopcode.org
# Makefile helpers for mercurial

hg-miss:
	${MAKE} hg-miss2 | grep -v sys| grep -v git| grep -v maemo

hg-miss2:
	@-hg st . | grep -e vala$$ -e mk$$ | grep ^? | grep -v config-user | cut -c 2- || true
	@-hg st . | grep -e \\.c$$ -e \\.h$$ | grep -v vapi | grep ^? | grep -v r_userconf | cut -c 2- || true
	@-hg st . | grep -e \\.vapi$$ -e \\.acr$$ -e README$$ -e TODO$$ | grep ^? | cut -c 2- || true

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

hg-ci:
	@hg diff > /tmp/diff
	@hg ci
