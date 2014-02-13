#!/bin/bash

git remote | grep upstream &> /dev/null
if [ $? -ne 0 ]; then
	git remote add upstream https://github.com/radare/radare2.git
fi
git fetch upstream
git rebase --onto master upstream/master
