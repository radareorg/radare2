all: reg

reg:
	gcc -L../../util -I ../../include -Wl,-R.. -L.. test.c -lr_util -lr_reg -o reg

clean:
	rm -f test a.out
