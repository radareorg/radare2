#!/bin/sh
# pancake script to sync a git repo from a mercurial one
# hg-git seems broken as long as git is more restrictive in author names
# so... i just rewrote it from scratch to push commits by blocks

GITDIR=radare2.git
GITPUSH=git+ssh://git@github.com/radare/${GITDIR}
GITPULL=git://github.com/radare/${GITDIR}

getgittip() {
	cd ${GITDIR}
	git log -1|tail -n1 |awk -F 'r2:hg:' '{print $2}'
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
	hg log -v -r ${HG_TIP} -r $((${GIT_HG_TIP}+1)) > /tmp/commitmsg
	echo >> /tmp/commitmsg
	echo "mk/gitpush.sh: imported from r2:hg:${HG_TIP}" >> /tmp/commitmsg

	cd ${GITDIR}
	rm -rf *
	hg clone .. tmpdir
	cp -rf tmpdir/* .
	rm -rf tmpdir
	DELETED=$(git status | grep deleted |cut -d : -f 2)
	git add *
	[ -n "${DELETED}" ] && git rm ${DELETED}
	git commit -F /tmp/commitmsg
	git push ${GITPUSH}
fi
