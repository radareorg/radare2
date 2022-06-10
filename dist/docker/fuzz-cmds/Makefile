all:
	echo "make [build,rebuild,fuzz]"
	$(MAKE) build
	$(MAKE) fuzz

build:
	docker build -t r2fuzz .

rebuild:
	docker build -t r2fuzz --no-cache .

fuzz run:
	docker run -ti r2fuzz

.PHONY: all build rebuild fuzz run
