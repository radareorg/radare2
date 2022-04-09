BIN=rlcc

all:
	$(CC) -o $(BIN) -I../../../shlr/mpc ../../../shlr/mpc/mpc.c rlcc.c

test:
	./rlcc t/hello.r

clean:
	rm -f a.out $(BIN) *.o

