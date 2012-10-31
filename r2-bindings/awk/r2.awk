#!/usr/bin/awk -f

# Configuration
BEGIN {
	cpu="arm";
	bits=32
	offset=0
}
# API
function sys(cmd) {
	res = ""
	while((cmd|getline line)>0) {
 		res=res""line"\n"
	}
	close(x)
	return res
}

function dis(x) { return sys("rasm2 -o "offset" -b "bits" -a "cpu" -d '"x"'"); }
function asm(x) { return sys("rasm2 -o "offset" -b "bits" -a "cpu" '"x"'"); }
function symbols(x) { return sys("rabin2 -vs '"x"'"); }
function entry(x) { return sys("rabin2 -ve '"x"'"); }
#TODO: function write(data,off) { return sys("rabin2 -ve '"x"'"); }

function hexfind(file, x) {
	return sys("rafind2 -x '"x"' '"file"'|cut -d @ -f 2")
}

# Your program here
BEGIN {
	cpu="x86"
	op=dis("90903939");
	print("Commandline disassembler")
	split (hexfind("/bin/ls", "90"), results, / /)
	for (a in results) {
		print("--- "a)
	}
}
