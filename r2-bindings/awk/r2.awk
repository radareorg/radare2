#!/usr/bin/awk -f

# Configuration
BEGIN {
	file=""
	arch="arm"
	port=0
	host="localhost"
	bits=32
	offset=0
	iova=1
}

# API
function sys(cmd) {
	res = ""
	n=0
	while((cmd|getline line)>0) {
		n++
 		res=res""line"\n"
	}
	if(n==0) return 0
	return res
}

function chop(x) {
	gsub(/\n/,"",x);
	return x
}

function round(a) {a=(a < int(a)+0.5) ? int(a) : int(a+1)}
function ceil(a) {a=(a == int(a)) ? a : int(a)+1}
function dis(x) { return sys("rasm2 -o "offset" -b "bits" -a "arch" -d '"x"'"); }
function asm(x) { return sys("rasm2 -o "offset" -b "bits" -a "arch" '"x"'"); }
function symbols() { return sys("rabin2 -vqs '"file"'"); }
function entries() { return sys("rabin2 -vqe '"file"'"); }
function imports() { return sys("rabin2 -vqi '"file"'"); }
function strings() { return sys("rabin2 -vqz '"file"'"); }
function sections() { return sys("rabin2 -vqS '"file"'"); }
function num(x) { return 0+x }
function cmd(c) { return sys("r2 -qc '"cmd"' '"file"'") }
function read(off,num) { return sys("r2 -qc 'p8 "num"@"off"' '"file"'") }
function write(off,x) { return sys("r2 -wqc 'wx "x"@"off"' '"file"'") }
function prompt(x,y) {printf(x);getline y; return chop(y); }
function search_hex(x) { return sys("rafind2 -x '"x"' '"file"'") }
function search_str(x) { return sys("rafind2 -s '"x"' '"file"'") }

# session server
function r2open() {
	srand()rand()
	port=1024+int(8192*rand())
	if(system("r2 -qc .:"port" "file" >/dev/null 2>&1 &"))
		return 0
	return port
}
function r2cmd(port, cmd) { return sys("r2 -qc'\".:"host":"port" "cmd"\"' -") }
function r2close(port) { r2cmd(port,"q!") }
