all: node_modules
	(sleep 1; open http://localhost:8080/p/ ) &
	r2 -qc '#!pipe node index.js' /bin/ls

node_modules:
	mkdir -p node_modules
	npm install
