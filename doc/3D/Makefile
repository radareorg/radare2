RUN=square pyramid logo

TARGETS=$(addsuffix .r2, $(addprefix 3D-,${RUN}))

all: $(TARGETS)

*.r2:
	r2 -qi $@ --

.PHONY: *.r2
