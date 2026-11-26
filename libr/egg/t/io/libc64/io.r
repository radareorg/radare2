#if LLVM
read@extern(i64, i32, ptr, i64);
write@extern(i64, i32, ptr, i64);
exit@extern(void, i32);
#else
read@syscall(read);
write@syscall(write);
exit@syscall(exit);
#endif
