# Workflow with r2r-overlay
# =========================
#
# Patch r2 to fix an issue, but then travis fails :-(. Don't worry.
# When staying in the branch of your PR enter t/ and:
#
# - Type `make` to grab the r2r repo
# - Fix the scripts in ../radare2-regressions/t*
# - Just type `make` again to get the overlay directory updated from r2r
# - git commit -a -m '...' ; git push
#
# From time to time we will want to merge those overlays into r2r:
#
# - When in master branch, type `make`
#

all: ../radare2-regressions
	cd ../radare2-regressions ; $(SHELL) ./overlay.sh auto

run tests:
	$(MAKE) -C ../radare2-regressions radare2

../radare2-regressions:
	cd .. ; git clone -q --depth 1 https://github.com/radare/radare2-regressions

create overlay:
	cd ../radare2-regressions ; $(SHELL) ./overlay.sh create

apply:
	cd ../radare2-regressions ; $(SHELL) ./overlay.sh apply
	git rm -rf overlay
	cd ../radare2-regressions ; git commit -a -m "move overlay into r2r"
	# git commit -a -m "move overlay into r2r"
	@echo
	@echo "Now commit this overlay purge with other changes"
	@echo

.PHONY: overlay apply create run tests all
