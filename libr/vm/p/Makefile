PLUGINS=x86.16 x86.32 x86.64 arm.32

all: plugins.h

plugins.h:
	:> plugins.h
	for a in ${PLUGINS} ; do \
		echo "static const char *vmprofile_$${a} = \\" | sed -e 's,\.,_,g' > $${a}.h ; \
		cat $${a}.vm | sed -e 's,^,  ",' -e 's,\.,_,g' -e 's,$$,\\n",g' >> $${a}.h ; \
		echo ";" >> $${a}.h ; \
		echo "#include \"$${a}.h\"" >> plugins.h ; \
	done

clean:
	rm -f *.h
