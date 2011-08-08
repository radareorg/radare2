#
# syscall implementation example
#
# Use of the preprocessor:
# $ spp -Darch=x64 rawsys64.r | rcc | rasm2 -
#

<{switch arch}>
<{case x86}>
  # 32 bits
  write@syscall(4);
  exit@syscall(1);
  @syscall() {
	: movl $`.arg`, %eax
	: int $0x80
  }
<{case x64}>
  # 64 bits
  @syscall() {
	: mov $`.arg`, %rax
	: syscall
  }
  write@syscall(1);
  exit@syscall(60);
<{endswitch}>

main@global(64,64)
{
	# raw syscall access for fun
	write($1, "Hello World\n", $12);
	exit($0);
}
