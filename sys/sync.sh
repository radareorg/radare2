#!/bin/sh

if ! git remote | grep upstream > /dev/null
then 
    git remote add upstream https://github.com/radareorg/radare2.git
fi
test -d radare2 && git fetch upstream && git rebase --onto master upstream/master
