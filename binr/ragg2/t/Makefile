R=../ragg2

all:
	${MAKE} hello

hello:
	rm -f a.out
	$R -s hello.r | tee hello.s
	$R -f mach0 -o a.out hello.r
	-./a.out ; RET=$$? ; if [ $$RET = 0 ]; then echo It Works ; else echo Oops.. Fail ; fi

hi:
	rm -f a.out
	$R -s hi.r
	$R -f mach0 -o a.out hi.r
	-./a.out ; RET=$$? ; if [ $$RET = 0 ]; then echo It Works ; else echo Oops.. Fail ; fi

customsyscall:
	rm -f a.out
	$R -s customsyscall.r
	$R -f mach0 -o a.out customsyscall.r
	-./a.out ; RET=$$? ; if [ $$RET = 2 ]; then echo It Works ; else echo Oops.. Fail ; fi

exithello:
	rm -f a.out
	$R -s exithello.r
	$R -f mach0 -o a.out exithello.r
	-./a.out ; RET=$$? ; if [ $$RET = 2 ]; then echo It Works ; else echo Oops.. Fail ; fi
