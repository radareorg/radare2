BIN=rlcc

all:
	$(CC) -o $(BIN) -Impc mpc/mpc.c rlcc.c

test:
	./rlcc t/hello.r

clean:
	rm -f a.out $(BIN) *.o

