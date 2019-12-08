all: node_modules
	$(shell npm bin)/r2r

node_modules:
	npm install >/dev/null

fix:
	npm install > /dev/null
	$(shell npm bin)/r2r -i

run:
	time $(shell npm bin)/r2r
