#!/bin/sh
CS_URL="$1" # url
CS_BRA="$2" # branch name
CS_TIP="$3" # tip commit
CS_REV="$4" # revert
CS_ARCHIVE="$5" # download archived tip
CS_DEPTH_CLONE=512

git_assert() {
	git --help > /dev/null 2>&1
	if [ $? != 0 ]; then
		echo "ERROR: Cannot find git command in PATH"
		if [ "$1" = check ]; then
			return 1
		fi
		exit 1
	fi
	return 0
}

fatal_msg() {
	echo "[capstone] $1"
	exit 1
}

patch_capstone() {
	echo "[capstone] Applying patches..."
	if [ "$CS_BRA" = next ]; then
		CV=v6
	else
		CV=v5
	fi
	if [ -n "`ls ../capstone-patches/$CV/ 2> /dev/null`" ]; then
		for patchfile in ../capstone-patches/$CV/*.patch ; do
			echo "Patch $patchFile"
			patch -p 1 < "${patchfile}"
		done
	fi
}

parse_capstone_tip() {
	if [ -n "${CS_REV}" ]; then
		HEAD="$(git rev-parse --verify HEAD^)"
	else
		HEAD="$(git rev-parse --verify HEAD)"
	fi
	BRANCH="$(git rev-parse --abbrev-ref HEAD)"
}

download_archive() {
	echo '[capstone] Downloading capstone snapshot...' >&2
	wget --help > /dev/null 2>&1
	if [ $? = 0 ]; then
		DLBIN="wget -O"
	else
		DLBIN="curl -o"
	fi
	${DLBIN} .cs_tmp.zip "$CS_ARCHIVE" || fatal_msg 'Cannot download archived capstone'
	unzip .cs_tmp.zip || exit 1
	mv "capstone-$CS_TIP" capstone
}

git_clone() {
	git_assert
	echo '[capstone] Cloning capstone from git...' >&2
	git clone --quiet --single-branch --branch "${CS_BRA}" \
	    --depth "$CS_DEPTH_CLONE" "${CS_URL}" capstone \
	|| fatal_msg 'Cannot clone capstone from git'
}

get_capstone() {
	if [ -d capstone ]; then
		return
	fi
	if [ -f capstone ]; then
		rm -f capstone
	fi
	git_clone || fatal_msg 'Clone failed'
	cd capstone || fatal_msg 'Failed to chdir'
	parse_capstone_tip
	cd ..
}

update_capstone_git() {
	cd capstone || fatal_msg 'Failed to chdir'
	git checkout "${CS_BRA}" || fatal_msg "Cannot checkout to branch $CS_BRA"
#	if [ -n "${CS_TIP}" ]; then
#		# if our shallow clone not contains CS_TIP, clone until it
#		# contain that commit.
#		cur_depth="$CS_DEPTH_CLONE"
#		until git cat-file -e "${CS_TIP}^${commit}"; do
#			cur_depth=$(( cur_depth + 10 ))
#			git pull --depth="$cur_depth"
#		done
#		git reset --hard "${CS_TIP}"
#	fi
	if ! git show --oneline "${CS_TIP}" &>/dev/null ; then
		git fetch
	fi
	git reset --hard "${CS_TIP}"
	if [ -n "${CS_REV}" ]; then
		if ! git config user.name ; then
			git config user.name "radare"
			git config user.email "radare@radare.org"
		fi
		export EDITOR=cat git revert --no-edit "${CS_REV}"
	fi
	cd ..
}

### MAIN ###

pkg-config --cflags capstone > /dev/null 2>&1
if [ $? = 0 ]; then
	echo "Warning: You have system-wide capstone installation, but im gonna clone a new copy of it"
	echo "Warning: Use ./configure --with-syscapstone # in case you prefer to use system one"
#	exit 0
fi

if [ -n "${CS_ARCHIVE}" ]; then
	echo "CS_ARCHIVE=${CS_ARCHIVE}"
else
	echo
	echo "Run 'make CS_COMMIT_ARCHIVE=1' to download capstone with wget/curl instead of git"
	echo
fi

if [ -z "${CS_ARCHIVE}" ]; then
	git_assert check
	if [ $? != 0 ]; then
		export CS_ARCHIVE="https://github.com/aquynh/capstone/archive/$3.zip"
	fi
fi

if [ -d capstone -a ! -d capstone/.git ] || [ "$(git --git-dir capstone/.git rev-parse --verify HEAD > /dev/null 2>&1)" = "${CS_TIP}" ]; then
	echo "[capstone] Nothing to do"
	exit 0
fi
if [ -n "${CS_ARCHIVE}" ]; then
	download_archive
else
	git_assert
	get_capstone
	[ -d capstone/.git ] && update_capstone_git
fi
cd capstone || fatal_msg 'Cannot change working directory'
patch_capstone
cd -
