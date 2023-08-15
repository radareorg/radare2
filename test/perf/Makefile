TIP=$(shell git log|head -n1|awk '{print $$2}')
CNT=$(shell git log|grep ^commit|wc -l | awk '{print $$1}')

all:
	mkdir -p logs
	r2r -o logs/$(CNT)-$(TIP).json -i ../db/perf
	cd logs && r2 -qi ../index.r2.js --
