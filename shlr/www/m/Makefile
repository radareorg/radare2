all:
	r2 -qe http.root=$$PWD -e http.ui= -c=H /bin/ls

sync up update:
	rm -f material.min.js
	wget http://www.getmdl.io/material.min.js
	rm -f material.min.css
	wget http://www.getmdl.io/material.min.css

dist:
	cd .. ; tar czvf r2mat.tar.gz m
