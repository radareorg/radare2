.PHONY: mpc mpc-clean clean-mpc mpc-sync sync-mpc
mpc:
	$(MAKE) -C mpc all

mpc-clean clean-mpc:
	$(MAKE) -C mpc clean

mpc-sync sync-mpc:
	wget -O mpc/mpc.c.dos https://raw.githubusercontent.com/orangeduck/mpc/master/mpc.c
	wget -O mpc/mpc.h.dos https://raw.githubusercontent.com/orangeduck/mpc/master/mpc.h
	sed "s/$$(printf '\r')\$$//" < mpc/mpc.c.dos > mpc/mpc.c
	sed "s/$$(printf '\r')\$$//" < mpc/mpc.h.dos > mpc/mpc.h
	rm -f mpc/*.dos

