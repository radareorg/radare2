#INCDIR@alias(i/);

/*
   TODO: we need ragg2 to setup OS ARCH BITS environs
   use environment to set/get values
	OS@env(osx); 
	syscalls.r@include($OS);

   use ragg2 -I to add new include path
*/

#INCDIR@env(/usr/include/r_egg);
INCDIR@env(t); # INCDIR=t
sys.r@include($INCDIR); # find t/sys.r

main@global() {
	exit(43);
}
