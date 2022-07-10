#!/bin/sh

# r2pm
# Honor user environment
[ -z "${SUDO}" ] && SUDO=sudo
[ -z "${WGET}" ] && WGET=wget

r2 -qv > /dev/null 2>&1
if [ $? != 0 ]; then
	echo "Cannot find r2 in PATH"
	exit 1
fi

# Exported Vars
[ -z "${R2PM_OFFLINE}" ] && R2PM_OFFLINE=0
MAKE=make
[ -z "${CURL}" ] && CURL=curl
gmake --help >/dev/null 2>&1
[ $? = 0 ] && MAKE=gmake
export MAKE
export GLOBAL=0
export R2PM_JOBS=4
export R2PMCACHE="$HOME/.r2pm.cache"

if [ -z "${PYTHON}" ]; then
	python3 --version > /dev/null 2>&1
	if [ $? = 0 ]; then
		export PYTHON=python3
	else
		python --version > /dev/null 2>&1
		if [ $? = 0 ]; then
			export PYTHON=python
		else
			python2 --version > /dev/null 2>&1
			if [ $? = 0 ]; then
				export PYTHON=python2
			fi
		fi
	fi
fi

# Set R2_* Vars
eval $(r2 -H 2> /dev/null)
export R2_VERSION

[ -z "$R2PM_CLEAN_INSTALL" ] && export R2PM_CLEAN_INSTALL=0

R2PM=$0
R2PMCACHE_LOADED=0
if [ -f ~/.r2pm.cache ]; then
	. ~/.r2pm.cache
	export LIBEXT="$LIBEXT"
	LIBDIR="$LIBDIR"
	export R2CONFIGHOME="$R2CONFIGHOME"
	export R2DATAHOME="$R2DATAHOME"
	PREFIX="$PREFIX"
	if [ -z "${LIBEXT}" -o -z "${LIBDIR}" -o -z "${R2CONFIGHOME}" -o -z "${R2DATAHOME}" -o -z "${PREFIX}" ]; then
		echo "[r2pm] corrupted cache, please run r2pm cache"
	else
		R2PMCACHE_LOADED=1
	fi
fi
if [ "${R2PMCACHE_LOADED}" != 1 ]; then
	export LIBEXT="$R2_LIBEXT"
	LIBDIR="$R2_LIBDIR"
	export R2CONFIGHOME="$R2_RCONFIGHOME"
	export R2DATAHOME="$R2_RDATAHOME"
	PREFIX="$R2_PREFIX"
fi
BINDIR="${PREFIX}/bin/"
WRKDIR="$PWD"

# prefix
export R2PM_SYSPREFIX="${PREFIX}"
export R2PM_HOMEPREFIX="${R2DATAHOME}/prefix"
export R2PM_PREFIX="${R2PM_HOMEPREFIX}"

# bindir
export R2PM_HOMEBINDIR="${R2PM_HOMEPREFIX}/bin"
export R2PM_SYSBINDIR="${BINDIR}"

[ -z "${R2PM_BINDIR}" ] && R2PM_BINDIR=${R2PM_HOMEBINDIR}
export R2PM_BINDIR

# libdir
export R2PM_SYSLIBDIR="${LIBDIR}"

# plugdir
export R2PM_SYSPLUGIN_DIR="$R2_LIBR_PLUGINS"
export R2PM_USRPLUGIN_DIR="$R2_USER_PLUGINS"
[ -z "${R2PM_PLUGDIR}" ] && R2PM_PLUGDIR="${R2PM_USRPLUGIN_DIR}"
[ -z "${R2PM_PLUGDIR}" ] && R2PM_PLUGDIR="${R2DATAHOME}/plugins"

# www
export R2PM_SYSWWWROOT="`r2 -qc 'e http.root' -- 2> /dev/null`"
export R2PM_HOMEWWWROOT="${R2DATAHOME}/www/"
export R2PM_WWWROOT="${R2PM_HOMEWWWROOT}"

# pkgconfig
export PKG_CONFIG_PATH="${R2PM_HOMEPREFIX}/lib/pkgconfig:${R2PM_SYSLIBDIR}/pkgconfig:${PKG_CONFIG_PATH}"
export CFLAGS="-I${R2PM_HOMEPREFIX}/include"
export LDFLAGS="-L${R2PM_HOMEPREFIX}/lib"

export R2PM_PYPATH="${R2PM_PREFIX}/python"
export R2PM_OLDPWD="${PWD}"

export RHOMEDIR="$R2_RCONFIGHOME"

if [ "`uname`" = Darwin ]; then
	export LD_LIBRARY_PATH="${R2PM_HOMEPREFIX}/lib"
else
	export DYLD_LIBRARY_PATH="${R2PM_HOMEPREFIX}/lib"
fi

# Anything defined here will cause master not to be checked out or pulled
export R2PM_GITSKIP="${R2PM_GITSKIP}"

# Global Vars
TRAVIS_TYPE=XX
TRAVIS_JOB=86948888
IS_SYSPKG=0
[ -z "$R2PM_USRDIR" ] && R2PM_USRDIR="${R2DATAHOME}/r2pm"
R2PM_ETCD="${R2CONFIGHOME}/radare2rc.d"

# TODO. support system plugin installs R2PM_PLUGDIR="${R2PM_SYSLIBDIR}/radare2/last"
if [ -z "${R2PM_GITDIR}" ]; then
	R2PM_GITDIR="${R2PM_USRDIR}/git"
fi
if [ -z "${R2PM_DBDIR}" ]; then
	if [ -d "${R2DATAHOME}/r2pm/db" ]; then
		R2PM_DBDIR="${R2DATAHOME}/r2pm/db"
	fi
fi
if [ -z "${R2PM_DBDIR}" ]; then
	if [ -d "${PREFIX}/share/radare2/last/r2pm" ]; then
		R2PM_DBDIR="${PREFIX}/share/radare2/last/r2pm/"
	fi
fi
if [ -f "d/baleful" ]; then
	R2PM_DBDIR="$(pwd)/d/"
fi

# R2_580 - deprecate `install`, `info`... just use flags like in the C program
help() {
	cat <<HELP
Usage: r2pm [init|update|cmd] [...]
Commands:
 -I,info                     information about repository and installed packages
 -i,install <pkgname>        install or update package in your home (pkgname=all)
 -gi,global-install <pkg>    install or update package system-wide
 -gu,global-uninstall <pkg>  uninstall pkg from systemdir
 -U,upgrade                  r2pm -U (upgrade all outdated plugins)
 -u,uninstall <pkgname>      r2pm -u baleful (-uu to force)
 -l,list                     list installed pkgs
 -r,run [cmd ...args]        run shell command with R2PM_BINDIR in PATH
 -s,search [<keyword>]       search in database
 -v,version                  show version
 -h,help                     show this message
 -H variable                 show value of given variable
 -c,clean ([git/dir])        clear source cache (GITDIR)
 -ci (pkgname)               clean install of given package
 -cp                         clean the user's home plugin directory
 -d,doc [pkgname]            show documentation for given package
 init | update ..            initialize/update database
 cd [git/dir]                cd into given git (see 'r2pm ls')
 ls                          ls all cloned git repos in GITDIR
 purge                       self destroy all r2 installations
 cache                       cache contents of r2 -H to make r2pm r2-independent
Environment:
 SUDO=sudo                   use this tool as sudo
 R2PM_PLUGDIR=${R2PM_PLUGDIR}
 R2PM_BINDIR=${R2PM_BINDIR}
 R2PM_OFFLINE=0              disabled by default, avoid init/update calls if set to !=0
 R2PM_NATIVE=0               set to 1 to use the native C codepath for r2pm
 R2PM_DBDIR=${R2PM_DBDIR}
 R2PM_GITDIR=${R2PM_GITDIR}
 R2PM_GITSKIP=${R2PM_GITSKIP}
HELP
}

confirm() {
	printf "$@ (y/N)? "
	read A
	if [ "$A" = y -o "$A" = Y ]; then
		return 0
	fi
	return 1
}

purgeR2() {
	P="$1"
	BINS="r2 radare2 rabin2 rafind2 r2pm "
	cd "$P/bin" && rm -f ${BINS}
	cd "$P/lib" && rm -f libr_*
	cd "$P/lib" && rm -rf radare2
	cd "$P/lib64" && rm -f libr_*
	cd "$P/lib64" && rm -rf radare2
	cd "$P/share" && rm -rf radare2
	cd "$P/share/man" && rm -rf man1/r*2.1
	cd "$P/share/doc" && rm -rf radare2
}

countDown() {
	M="$1"
	C="$2"
	printf "$M"
	while : ; do
		printf "$C "
		C=$(($C-1))
		[ "$C" = 0 ] && break
	done
	echo 'Go!'
}

thePurge() {
	confirm "Do you wanna purge r2 completely from your system and home?"
	if [ $? != 0 ]; then
		echo "Aborted." > /dev/stderr
		exit 1
	fi
	countDown "Self destroying in" 3
	confirm "> Delete $RHOMEDIR" && (
		rm -rf "$RHOMEDIR"
	)
	R2PATHS="${PREFIX}:/usr:/usr/local:/opt/radare2:${RHOMEDIR}/prefix:/"
	IFS=:
	for a in $R2PATHS ; do
		if [ -x "${a}/bin/radare2" ]; then
			confirm "> Delete r2 from ${a}" && (
				purgeR2 "$a"
			)
		fi
	done
	unset IFS
}

upgradeOutdated() {
	LINES=`r2 -qcq -- 2>&1 | grep r2pm | sed -e 's,$,;,g'`
	if [ -n "${LINES}" ]; then
		eval "${LINES}"
	else
		echo "Nothing to upgrade"
	fi
}

r2pm_update() {
	[ "${R2PM_OFFLINE}" != 0 ] && return
	[ -z "$R2PM_DBDIR" ] && R2PM_DBDIR="${R2PM_USRDIR}/db"
	mkdir -p "${R2PM_GITDIR}"
	mkdir -p "${HOME}/.config"
	cd "${R2PM_GITDIR}" || return 1
	if [ -d radare2-pm ]; then
		cd radare2-pm
		git reset --hard @^^ > /dev/null 2>&1
		git pull
	else
		echo git clone https://github.com/radareorg/radare2-pm
		git clone -q --depth=10 --recursive https://github.com/radareorg/radare2-pm
		cd radare2-pm
		pwd
	fi
	for a in "${R2PM_DBDIR}" "${R2PM_USRDIR}"/db2/*/db ; do
		if [ -d "$a" ]; then
			echo "[r2pm] Updating package database $a ..."
			( cd $a ; git pull )
		fi
	done

	if [ -d "${R2PM_DBDIR}" ] && [ ! -L "${R2PM_DBDIR}" ]; then
		# that's weird, it should be a symlink
		rm -f "${R2PM_DBDIR}/"*
		rmdir "${R2PM_DBDIR}"
	else
		# doesn't exist, is a file or symlink
		rm -f "${R2PM_DBDIR}"
	fi

	ln -fs "${R2PM_GITDIR}/radare2-pm/db" "${R2PM_DBDIR}"
}

case "$1" in
init|up|update)
	r2pm_update
	exit 0
	;;
esac

# command-line flags that work without initialized database
case "$1" in
-v|version)
	echo "r2pm ${R2_VERSION}"
	exit 0
	;;
help|-h)
	help
	exit 0
	;;
-H)
	if [ -z "$2" ]; then
		echo "Usage: r2pm -H [VARNAME]"
		echo "Variables: R2PM_PLUGDIR R2PM_BINDIR R2PM_DBDIR R2PM_GITDIR"
		exit 1
	fi
	eval echo "\$$2"
	exit 0
	;;
esac

if [ ! -d "${R2PM_DBDIR}" ]; then
	if [ "${R2PM_OFFLINE}" != 0 ]; then
		echo "Run 'r2pm init' to initialize the package repository"
		exit 1
	else
		r2pm init
	fi
else
	# use timestamp file
	S="${R2PM_GITDIR}"/.stamp
	N=`date +%Y%m%d%H`
	if [ "`cat $S 2>/dev/null`" != "$N" ]; then
		r2pm_update > /dev/null 2>&1
		echo $N > "$S"
	fi
fi

mkdir -p "${R2PM_USRDIR}/pkg/"
mkdir -p "${R2PM_GITDIR}"
mkdir -p "${R2PM_PLUGDIR}"
mkdir -p "${R2PM_BINDIR}"

R2PM_SYSPKG() {
	IS_SYSPKG="$1"
	echo "R2PM_SYSPKG is going to be deprecated" >&2
}

R2PM_DESC() {
	:
}

R2PM_SUDO() {
	if [ "${GLOBAL}" = 1 ]; then
		${SUDO} "$@"
	else
		"$@"
	fi
}
export R2PM_SUDO="R2PM_SUDO"

R2PM_List() {
	cd "${R2PM_USRDIR}/pkg"
	if [ -n "$1" ]; then
		ls | grep -i "$1"
	else
		ls | cat
	fi
}

R2PM_Search() {
	#helper for pretty printing tabbed lists
	if type "column" > /dev/null; then
		cols() { column -s `printf "\t"` -t; }
	else
		cols() { cat ; }
	fi
	for a in "${R2PM_DBDIR}" "${R2PM_USRDIR}"/db2/*/db ; do
		[ -d "$a" ] || continue
(
		cd "${a}"
		if [ -n "$1" ]; then
			grep R2PM_DESC * /dev/null | sed -e "s,:R2PM_DESC,    `printf " \t"`," -e 's,",,g' | grep -i "$1"
		else
			grep R2PM_DESC * /dev/null | sed -e "s,:R2PM_DESC,    `printf " \t"`," -e 's,",,g' | cols
		fi
)
	done
}

R2PM_TGZ() {
	URL="$1"
	TARBALL="`basename $1`"
	if [ -z "$2" ]; then
		DIR="`echo ${TARBALL} | awk -F .t '{print $1}'`"
	elif [ "${2%${2#?}}"x = '/x' ]; then
		DIR="${2#?}"
	else
		DIR="$2"
	fi
	if [ -n "$3" ]; then
		TARBALL="$3"
	fi
	cd "${R2PM_GITDIR}"
	if [ "$ACTION" = clean ]; then
		rm -f "${TARBALL}"
		exit 0
	fi
	${WGET} -O ${TARBALL} -c "${URL}"
	if [ -d "${DIR}" ]; then
		echo "Already uncompressed."
	else
		if [ "`echo ${URL} | grep -e tgz -e tar.gz`" ]; then
			tar xzvf "${TARBALL}"
		elif [ "`echo ${URL} | grep -e .tbz2 -e tar.bz2`" ]; then
			tar xjvf "${TARBALL}"
		elif [ "`echo ${URL} | grep -e .txz -e tar.xz`" ]; then
			tar xJvf "${TARBALL}"
		elif [ "`echo ${URL} | grep -e .txz -e tar`" ]; then
			tar xvf "${TARBALL}"
		elif [ "`echo ${URL} | grep -e .zip`" ]; then
			if [ -n "$2" ] && [ "${2%${2#?}}"x != '/x' ]; then
				unzip -d "${DIR}" -o "${TARBALL}"
			else
				unzip "${TARBALL}"
			fi
		else
			echo "Dunno"
			exit 1
		fi
	fi
	cd "${DIR}" || R2PM_FAIL "Oops"
}

R2PM_DOC() {
	R2PM_DOC="$@"
}

R2PM_GIT() {
	[ -z "${NAME}" -o "$ACTION" = clean ] && return
	URL="$1"
	if [ -z "$2" ]; then
		DIR="`basename $1`"
	else
		DIR="$2"
	fi
	cd "${R2PM_GITDIR}"
	if [ -d "${DIR}" ]; then
		cd "${DIR}"
		if [ -z "${R2PM_GITSKIP}" ]; then
			git checkout master
			git pull
		fi
	else
		git clone -q --depth 1 --recursive "${URL}" "${DIR}" || R2PM_FAIL "Oops"
		cd "${DIR}" || R2PM_FAIL "Oops"
	fi
	r2 -qv | grep -q git || { # r2 >= 4.5
		if [ -z "${R2PM_GITSKIP}" ]; then
			git checkout "r2-${R2_VERSION}"
			git pull
		fi
	}
}

R2PM_SVN() {
	URL="$1"
	if [ -z "$2" ]; then
		DIR="${NAME}"
	else
		DIR="$2"
	fi
	cd "${R2PM_GITDIR}" || exit 1
	if [ -d "${DIR}" ]; then
		cd "${DIR}"
		svn up
	else
		svn co "${URL}" "${DIR}"
		cd "${DIR}" || R2PM_FAIL "Oops"
	fi
}

R2PM_FAIL() {
	printf "\033[31mERROR: \033[32m$@\033[0m\n"
	exit 1
}

R2PM_BEGIN() {
	R2PM_GIT=""
	R2PM_DEPS=""
}

R2PM_Info() {
	if [ -n "${R2PM_DBDIR}" -a -d "${R2PM_DBDIR}" ]; then
		echo "# Repository Database:"
		cd "${R2PM_DBDIR}"
		printf "# $(ls |wc -l) Packages\n" >&2
	fi
	cd "${R2PM_USRDIR}/pkg"
	echo "# Installed:"
	printf "# %s Packages\n# " "$(ls | wc -l)" >&2
	du -hs "${HOME}/.config/radare2" >&2
}

R2PM_REGISTER() {
	date > "${R2PM_USRDIR}/pkg/$NAME"
}

R2PM_UNREGISTER() {
	rm -f "${R2PM_USRDIR}/pkg/$NAME"
}

R2PM_END() {
	if [ -n "${NAME}" ]; then
		echo "${ACTION} Done For ${NAME}"
	fi
}

R2PM_DEPS() {
	if [ -n "${R2PM_IGNORE_DEPS}" ]; then
		return
	fi
	if [ "$ACTION" != Install ]; then
		return
	fi
	S="\$"
	for a in "$@" ; do
		echo "DEPENDS: $a"
		doInstall=0
		if [ "$R2PM_CLEAN_INSTALL" = 1 ]; then
			doInstall=1
		else
			r2pm -l "$a${S}" | grep "^$a"
			isInstalled=$?
			doInstall=0
			if [ $isInstalled = 1 ]; then
				doInstall=1
			fi
			if [ "${R2PM_UPGRADE}" ]; then
				doInstall=1
			fi
		fi
		if [ "$doInstall" = 1 ]; then
			${R2PM} clean "$a"
			export R2PM_CLEAN_INSTALL=1
			if [ "${GLOBAL}" = 1 ]; then
				${R2PM} global-install "$a"
			else
				${R2PM} install "$a"
			fi
		fi
	done
}

pkgFilePath() {
	for a in "${R2PM_DBDIR}" "${R2PM_USRDIR}"/db2/*/db ; do
		if [ -f "$a/$1" ]; then
			echo "$a/$1"
			return
		fi
	done
}

r2pm_doc() {
	if [ -z "$1" ]; then
		echo "Usage: r2pm -d [package]     # show docs on [package] (see r2pm -l)"
		exit 1
	else
		FILE="$(pkgFilePath "$1")"
		if [ -f "${FILE}" ]; then
			. "${FILE}"
			echo "${R2PM_DOC}"
		fi
	fi
}

r2pm_install() {
	r2pm_update
	FILE="$(pkgFilePath "$2")"
	if [ -f "${FILE}" ]; then
		NAME="$2"
		ACTION=Install
		export PATH="${R2PM_HOMEBINDIR}:${PATH}"
		. "${FILE}"
		R2PM_INSTALL
		R2PM_REGISTER
	else
		echo "Cannot find $2"
		exit 1
	fi
}

r2pm_uninstall() {
	if [ -z "$2" ]; then
		echo "Usage: r2pm -u [package]  # uninstall [package]"
		exit 1
	else
		FILE="`pkgFilePath $2`"
		if [ -f "${FILE}" ]; then
			NAME="$2"
			ACTION=Uninstall
			. "${FILE}"
			R2PM_UNINSTALL
			if [ $? = 0 ]; then
				R2PM_UNREGISTER
			else
				echo Oops
			fi
		else
			echo "Unable to find package template for $2." >&2
			echo "Use -uu to remove it from the database." >&2
		fi
	fi
}

export PYTHON_PATH="${R2PM_PYPATH}:${PYTHON_PATH}"

case "$1" in
-I|info)
	R2PM_Info
	;;
-i|install)
	if [ -z "$2" ]; then
		echo "Usage: r2pm -i [package]  # install [package]"
		exit 1
	elif [ "$2" = "all" ]; then
		for a in `cd ${R2PM_DBDIR} && ls` ; do
			r2pm_install "$a"
			if [ "$?" != 0 ]; then
				printf "\033[31mERROR: Installation failed for $a\033[0m\n"
			fi
		done
	else
		A1="$1"
		while [ -n "$2" ] ; do
			r2pm_install $A1 "$2"
			shift
		done
	fi
	;;
-uu)
	if [ -z "$2" ]; then
		echo "Usage: r2pm -uu [pkgname] # force uninstall given package"
	else
		FILE="${R2PM_USRDIR}/pkg/$2"
		$0 -u $2 2> /dev/null
		rm -f "${FILE}"
	fi
	;;
-u|uninstall)
	r2pm_uninstall "$@"
	;;
-l|list)
	R2PM_List "$2"
	;;
-s|search)
	R2PM_Search "$2"
	;;
-r|run)
	shift
	PATH="${R2PM_BINDIR}:${PATH}" "$@"
	exit $?
	;;
-v|version)
	echo "r2pm ${R2_VERSION}"
	;;
-gi|-cgi|-gci|global-install)
	GLOBAL=1
	R2PM_PREFIX="${R2PM_SYSPREFIX}"
	#R2PM_PLUGDIR="${R2PM_SYSLIBDIR}/radare2/${R2_VERSION}/"
	R2PM_PLUGDIR="${R2PM_SYSPLUGIN_DIR}"
	R2PM_BINDIR="${R2PM_SYSBINDIR}"
	R2PM_WWWROOT="${R2PM_SYSWWWROOT}"
	#TODO set R2PM_ETCD= to a "global" radare2rc.d
	if [ ! -d "${R2PM_PLUGDIR}" ]; then
		mkdir -p "${R2PM_PLUGDIR}"
	fi
	r2pm_install "$@"
	;;
-gu|-cgu|-gcu|global-uninstall)
	GLOBAL=1
	R2PM_PREFIX="${R2PM_SYSPREFIX}"
	#R2PM_PLUGDIR="${R2PM_SYSLIBDIR}/radare2/${R2_VERSION}/"
	R2PM_PLUGDIR="${R2PM_SYSPLUGIN_DIR}"
	R2PM_BINDIR="${R2PM_SYSBINDIR}"
	R2PM_WWWROOT="${R2PM_SYSWWWROOT}"
	#TODO set R2PM_ETCD= to a "global" radare2rc.d
	r2pm_uninstall "$@"
	;;
-cp)
	if [ -n "${R2PM_PLUGDIR}" ]; then
		rm -f "${R2PM_PLUGDIR}/*"
	fi
	;;
-ci)
	shift
	export R2PM_CLEAN_INSTALL=1
	${R2PM} clean $*
	${R2PM} install $*
	;;
-c|clean)
	if [ -n "$2" ]; then
		RC=0
		while [ -n "$2" ]; do
			echo "Cleaning $2..."
			FILE="$(pkgFilePath "$2")"
			if [ -f "${FILE}" ]; then
				NAME="$2"
				ACTION=clean
				export PATH="${R2PM_HOMEBINDIR}:${PATH}"
				. "${FILE}"
				echo $FILE TGZ=$R2PM_TGZ
			else
				echo "Cannot find $FILE" >&2
				RC=1
			fi

			if [ -d "${R2PM_GITDIR}/$2" ]; then
				echo "Cleaning up ${R2PM_GITDIR}/$2..."
				rm -rf "${R2PM_GITDIR}/$2"
			else
				echo "Cannot find $2 in ${R2PM_GITDIR}" >&2
				RC=1
			fi
			shift
		done
		exit $RC
	else
		R2PM_List radare2 | grep radare2
		if [ $? != 0 ]; then
			echo "Press enter to remove the GITDIR or ^C to cancel operation"
			read A
			rm -rf "${R2PM_GITDIR}"
			mkdir -p "${R2PM_GITDIR}"
		else
			echo "r2 is installed with r2pm, do not clean the cache to avoid autodestruction"
			echo "do not disassemble do not disassemble do not disassemble do not disassemble"
			exit 1
		fi
	fi
	;;
cd)
	if [ -n "$2" ]; then
		cd "${R2PM_GITDIR}/$2"
		export R2PM_LEVEL=$((${R2PM_LEVEL}+1))
		echo "Entering into ${SHELL} level ${R2PM_LEVEL}."
		PS1="r2pm:${R2PM_LEVEL}:\W\$ " ${SHELL}
		echo "Exiting level ${R2PM_LEVEL}."
		exit 0
	else
		echo "Missing argument. See r2pm ls"
		exit 1
	fi
	;;
ls)
	if [ -d "${R2PM_GITDIR}" ]; then
		ls "${R2PM_GITDIR}"
	else
		echo "Cannot find ${R2PM_GITDIR}"
		exit 1
	fi
	;;
cache)
	echo "export LIBEXT=\"${LIBEXT}\"" > "${R2PMCACHE}"
	echo "export LIBDIR=\"${LIBDIR}\"" >> "${R2PMCACHE}"
	echo "export R2CONFIGHOME=\"${R2CONFIGHOME}\"" >> "${R2PMCACHE}"
	echo "export R2DATAHOME=\"${R2DATAHOME}\"" >> "${R2PMCACHE}"
	echo "export PREFIX=\"${PREFIX}\"" >> "${R2PMCACHE}"
	echo "[r2pm] r2 environment cached in ${R2PMCACHE}"
	;;
-U|upgrade)
	upgradeOutdated
	;;
-a|add)
	if [ "$2" = "help" ]; then
		printf '%s\n' \
			"Usage: r2pm -a [url] ([name]) # manage package repositories" \
			" $ r2pm -a https://github.com/foo/bar  # register bar repo" \
			" $ r2pm -a                             # list all repos" \
			" $ r2pm -a - bar                       # delete 'foo' repo"
		exit 1
	fi
	cd "${R2PM_DBDIR}"
	cd ..
	mkdir -p db2
	cd db2
	URL="$2"
	NAME="$3"
	if [ -n "$URL" -a -z "$NAME" ]; then
		NAME=`basename $URL`
	fi
	if [ -n "$URL" -a -n "$NAME" ]; then
		if [ "$URL" = "-" ]; then
			if [ -d "$NAME" ]; then
				rm -rf "$NAME"
				echo "Unregistered repository"
			else
				echo "Cannot find '$NAME'"
				exit 1
			fi
		else
			echo "Registering this db repository"
			if [ -d "$URL" ]; then
				cd "$URL"
				git pull
			else
				git clone -q --recursive --depth=2 "$URL" "$NAME"
			fi
			if [ ! -d "$NAME/db" ]; then
				echo "This is not an r2pm repository"
				rm -rf "$NAME"
				exit 1
			fi
		fi
	else
		ls
	fi
	cd "$WRKDIR"
	;;
-H)
	if [ -z "$2" ]; then
		echo "Usage: r2pm -H [VARNAME]"
		echo "Variables: R2PM_PLUGDIR R2PM_BINDIR R2PM_DBDIR R2PM_GITDIR"
		exit 1
	fi
	eval echo "\$$2"
	;;
purge)
	thePurge
	;;
-d|doc|--doc)
	r2pm_doc "$2"
	;;
*|help|-h)
	help
	;;
esac
