#!/bin/sh

GITDIR=radare2.git
GITPUSH=git+ssh://git@github.com/radare/${GITDIR}
GITPULL=git://github.com/radare/${GITDIR}

getgittip() {
	cd ${GITDIR}
	git log -1 | tail -n 1 | sed -e 's/.*r2:hg:\(.*\) .*/\1/'
	cd ..
}
gethgtip() {
	echo $(hg tip | grep changeset: | cut -d : -f 2)
}

if [ ! -d "${GITDIR}" ]; then
	git config --global user.name pancake
	git config --global user.email pancake@nopcode.org
	git clone ${GITPULL} ${GITDIR}
	[ ! $? = 0 ] && exit 1
else
	cd ${GITDIR}
	git pull ${GITPULL}
	cd ..
fi

GIT_HG_TIP=$(getgittip)
HG_TIP=$(gethgtip)

echo "GIT TIP: ${GIT_HG_TIP}"
echo "HG TIP:  ${HG_TIP}"

if [ "${GIT_HG_TIP}" = "${HG_TIP}" ]; then
	echo "Nothing to push"
else
	echo "Preparing hg to git..."
	hg log -v -r ${HG_TIP} -r ${GIT_HG_TIP} > /tmp/commitmsg
	echo >> /tmp/commitmsg
	echo "Imported from r2:hg:${HG_TIP}" >> /tmp/commitmsg

	cd ${GITDIR}
	rm -rf *
	hg clone .. tmpdir
	cp -rf tmpdir/* .
	rm -rf tmpdir
	DELETED=$(git status | grep deleted |cut -d : -f 2)
	git add *
	git rm ${DELETED}
	git commit -F /tmp/commitmsg
	git push ${GITPUSH}
fi
