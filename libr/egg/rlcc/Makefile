BIN=rlcc

all:
	$(CC) -o $(BIN) -Impc mpc/mpc.c rlcc.c

test:
	./rlcc t/hello.r

clean:
	rm -f a.out $(BIN) *.o

mpc-sync:
	rm -rf mpc
	git clone https://github.com/orangeduck/mpc.git
	git add mpc/mpc.h mpc/mpc.c
