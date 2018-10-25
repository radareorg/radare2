#!/bin/bash

if [ -z "$BASH" ]; then
	autoload bashcompinit
	bashcompinit
fi

_r2 () {
	local cur
	COMPREPLY=()
	cur=${COMP_WORDS[COMP_CWORD]}
	prv=${COMP_WORDS[COMP_CWORD-1]}
	case "$prv" in
	-a)
		COMPREPLY=( $(compgen -W "$(rasm2 -qL)" -- $cur))
		return 0
		;;
	-b)
		COMPREPLY=( $(compgen -W "8 16 32 64" -- $cur ))
		return 0
		;;
	-k)
		COMPREPLY=( $(compgen -W "$(r2 -qc 'e asm.os=?' --)" -- $cur ))
		return 0
		;;
	-e)
		COMPREPLY=( $(compgen -W "$(r2 -qceq --)" -- $cur ))
		return 0
		;;
	-F)
		COMPREPLY=( $(compgen -W "$(rabin2 -qL)" -- $cur ))
		return 0
		;;
	-H)
		COMPREPLY=( $(compgen -W "$(r2 -H |cut -d = -f 1)" -- $cur))
		return 0
		;;
	-p)
		COMPREPLY=( $(compgen -W "$(r2 -p?)" -- $cur ))
		return 0
		;;
	-D)
		COMPREPLY=( $(compgen -W "$(r2 -D?)" -- $cur ))
		return 0
		;;
	esac

	case "$cur" in
	-*)
		COMPREPLY=( $( compgen -W '-0 -a -A -b -B -c -C -d -D -e -f -F -h -hh -H -i -I -k -l -L -m -M -n -nn -N -o -q -p -P -R -s -S -t -u -v -V -w -z -zz' -- $cur))
		;;
	*)
		COMPREPLY=( $(compgen -f -- $cur))
		;;
	esac

	return 0
}

complete -F _r2 -o filenames r2
complete -F _r2 -o filenames radare2

_rasm2 () {
	local cur
	COMPREPLY=()
	cur=${COMP_WORDS[COMP_CWORD]}
	prv=${COMP_WORDS[COMP_CWORD-1]}
	case "$prv" in
	-a)
		COMPREPLY=( $(compgen -W "$(rasm2 -qL)" -- $cur))
		return 0
		;;
	-b)
		COMPREPLY=( $(compgen -W "8 16 32 64" -- $cur ))
		return 0
		;;
	-c)
		# TODO. grab -a and get asm.cpu=? output
		return 0
		;;
	-k)
		COMPREPLY=( $(compgen -W "$(r2 -qc 'e asm.os=?' --)" -- $cur ))
		return 0
		;;
	-s)
		COMPREPLY=( $(compgen -W "$(rasm2 -s?)" -- $cur ))
		return 0
		;;
	esac

	case "$cur" in
	-*)
		COMPREPLY=( $( compgen -W '-a -A -b -c -C -d -D -e -E -f -F -h -i -k-l -L -o -O -s -B -v -w -q' -- $cur))
		;;
	*)
		COMPREPLY=( $(compgen -f -- $cur))
		;;
	esac

	return 0
}

complete -F _rasm2 -o filenames rasm2

_rabin2 () {
	local cur
	COMPREPLY=()
	cur=${COMP_WORDS[COMP_CWORD]}
	prv=${COMP_WORDS[COMP_CWORD-1]}
	case "$prv" in
	-a)
		COMPREPLY=( $(compgen -W "$(rasm2 -qL)" -- $cur))
		return 0
		;;
	-b)
		COMPREPLY=( $(compgen -W "8 16 32 64" -- $cur ))
		return 0
		;;
	-c)
		# TODO. grab -a and get asm.cpu=? output
		return 0
		;;
	-k)
		COMPREPLY=( $(compgen -W "$(r2 -qc 'e asm.os=?' --)" -- $cur ))
		return 0
		;;
	-s)
		COMPREPLY=( $(compgen -W "$(r2 -qc 'e asm.syntax=?' --)" -- $cur ))
		return 0
		;;
	esac

	case "$cur" in
	-*)
		COMPREPLY=( $( compgen -W '-a -A -b -c -C -d -D -e -E -f -F -h -i -k-l -L -o -O -s -B -v -w -q' -- $cur))
		;;
	*)
		COMPREPLY=( $(compgen -f -- $cur))
		;;
	esac

	return 0
}

complete -F _rabin2 -o filenames rabin2

_rafind2 () {
	local cur
	COMPREPLY=()
	cur=${COMP_WORDS[COMP_CWORD]}
	case "$cur" in
	-*)
		COMPREPLY=( $( compgen -W '-a -b -e -f -h -m -M -n -r -s -S -t -v -x -X -z -Z' -- $cur))
		;;
	*)
		COMPREPLY=( $(compgen -f -- $cur))
		;;
	esac

	return 0
}

complete -F _rafind2 -o filenames rafind2

_radiff2() {
	local cur
	COMPREPLY=()
	cur=${COMP_WORDS[COMP_CWORD]}
	prv=${COMP_WORDS[COMP_CWORD-1]}
	case "$prv" in
	-a)
		COMPREPLY=( $(compgen -W "$(rasm2 -qL)" -- $cur))
		return 0
		;;
	-b)
		COMPREPLY=( $(compgen -W "8 16 32 64" -- $cur ))
		return 0
		;;
	esac
	case "$cur" in
	-*)
		COMPREPLY=( $( compgen -W '-a -A -AA -AAA -b -c -C -d -D -g -j -n -O -p -r -s -ss -S -t -x -v -V' -- $cur))
		;;
	*)
		COMPREPLY=( $(compgen -f -- $cur))
		;;
	esac

	return 0
}

complete -F _radiff2 -o filenames radiff2
