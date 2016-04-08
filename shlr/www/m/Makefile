all:
	r2 -qe http.root=$$PWD -e http.ui= -c=H /bin/ls

sync up update:
	rm -f material.min.js
	wget http://www.getmdl.io/material.min.js
	rm -f material.min.css
	wget http://www.getmdl.io/material.min.css

FILES=$(shell git ls-files .)

zip: clean
	zip -r radare2.zip $(FILES)

dist:
	cd .. ; tar czvf r2mat.tar.gz m

clean:
	rm -f *.gz *.zip

.PHONY: zip dist sync up update all clean
