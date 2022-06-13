all:
	echo "make [build,rebuild,fuzz]"
	$(MAKE) build
	$(MAKE) fuzz

build:
	docker build -t r2fuzz-asm .

rebuild:
	docker build -t r2fuzz-asm --no-cache .

shell:
	docker run -ti r2fuzz-asm bash

fuzz run:
	docker run -ti r2fuzz-asm

.PHONY: all build rebuild fuzz run
