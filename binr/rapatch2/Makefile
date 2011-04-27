all:
	gcc rapatch.c `pkg-config --cflags --libs r_core`

a: all
	cp /bin/ls ls
	./a.out ls patch.txt
	./ls

clean:
	rm -f a.out RaPatcher RaPatcher.c out.* ls
