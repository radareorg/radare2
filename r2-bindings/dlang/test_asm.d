import std.stdio;
import std.conv;
import r_asm;

void main() {
	auto a = new RAsm();
	a.use ("x86");
	a.set_bits (32);
	auto code = a.massemble ("mov eax, 33");
	writefln ("Code: '%s'", to!string (code.buf_hex));
}
