#!/bin/sh
cd $HOME/prg/radare2
IFS=:
for a in $PATH ; do
	if [ -x "$a/radare2" ]; then
		D=$(dirname `readlink /usr/local/bin/radare2`)
		cd "$D/../.."
		if [ -d libr/include ]; then
			git grep "$1" libr/include | grep -v '#include' | less -p "$1" -R
			exit 0
		fi
	fi
done
echo "Cant find r2"
