#!/bin/sh
CS_URL="$1" # url
CS_BRA="$2" # branch name
CS_TIP="$3" # tip commit
CS_REV="$4" # revert

if [ -d capstone -a ! -d capstone/.git ]; then 
	echo "[capstone] release with no git?"
	cd capstone
	for PATCH in ../capstone-patches/* ; do
		yes n | patch -Rp1 < $PATCH
	done
else 
	if [ ! -d capstone ]; then 
		git clone -b "${CS_BRA}" --depth 10 "${CS_URL}" capstone || exit 1
	fi
	cd capstone || exit 1
	if [ -n "${CS_REV}" ]; then
		HEAD="`git log|grep ^commit | head -n2|tail -n1 | awk '{print $2}'`"
	else
		HEAD="`git log|head -n1 | awk '{print $2}'`"
	fi
	if [ "${HEAD}" = "${CS_TIP}" ]; then
		echo "[capstone] Already in TIP, no need to update from git"
		exit 0
	fi
		echo "[capstone] Updating capstone from git..."
	echo "HEAD ${HEAD}"
	echo "TIP ${CS_TIP}"

	git reset --hard HEAD^^^
	git checkout "${CS_BRA}" || exit 1
	git pull
	if [ -n "${CS_TIP}" ]; then
		git reset --hard "${CS_TIP}"
	fi
	if [ -n "${CS_REV}" ]; then 
		if ! git config user.name ; then
			git config user.name "radare-travis"
			git config user.email "radare-travis@foo.com"
		fi
		EDITOR=cat git revert --no-edit ${CS_REV}
	fi
fi
