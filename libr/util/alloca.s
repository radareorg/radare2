	.file	"alloca.c"
	.local	buf
	.comm	buf,4,4
	.local	bufidx
	.comm	bufidx,4,4
	.local	bufnext
	.comm	bufnext,4,4
	.text
.globl r_alloca_init
	.type	r_alloca_init, @function
r_alloca_init:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	subl	$4, %esp
	call	.L3
.L3:
	popl	%ebx
	addl	$_GLOBAL_OFFSET_TABLE_+[.-.L3], %ebx
	subl	$12, %esp
	pushl	$30720
	call	malloc@PLT
	addl	$16, %esp
	movl	%eax, buf@GOTOFF(%ebx)
	cmpl	$0, buf@GOTOFF(%ebx)
	jne	.L2
	movl	$0, -8(%ebp)
	jmp	.L1
.L2:
	movl	buf@GOTOFF(%ebx), %eax
	movl	%eax, bufptr@GOTOFF(%ebx)
	movl	buf@GOTOFF(%ebx), %eax
	movl	%eax, bufnext@GOTOFF(%ebx)
	movl	buf@GOTOFF(%ebx), %eax
	addl	$30720, %eax
	movl	%eax, bufmax@GOTOFF(%ebx)
	movl	$1, -8(%ebp)
.L1:
	movl	-8(%ebp), %eax
	movl	-4(%ebp), %ebx
	leave
	ret
	.size	r_alloca_init, .-r_alloca_init
.globl r_alloca_bytes
	.type	r_alloca_bytes, @function
r_alloca_bytes:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$12, %esp
	call	.L6
.L6:
	popl	%ecx
	addl	$_GLOBAL_OFFSET_TABLE_+[.-.L6], %ecx
	movl	bufnext@GOTOFF(%ecx), %eax
	movl	%eax, -4(%ebp)
	movl	8(%ebp), %eax
	addl	bufnext@GOTOFF(%ecx), %eax
	movl	%eax, -8(%ebp)
	movl	-8(%ebp), %eax
	cmpl	bufmax@GOTOFF(%ecx), %eax
	jbe	.L5
	movl	$0, -12(%ebp)
	jmp	.L4
.L5:
	incl	bufidx@GOTOFF(%ecx)
	movl	bufidx@GOTOFF(%ecx), %edx
	movl	-8(%ebp), %eax
	movl	%eax, bufptr@GOTOFF(%ecx,%edx,4)
	movl	%eax, bufnext@GOTOFF(%ecx)
	movl	-4(%ebp), %eax
	movl	%eax, -12(%ebp)
.L4:
	movl	-12(%ebp), %eax
	leave
	ret
	.size	r_alloca_bytes, .-r_alloca_bytes
.globl r_alloca_str
	.type	r_alloca_str, @function
r_alloca_str:
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	subl	$20, %esp
	call	.L12
.L12:
	popl	%ebx
	addl	$_GLOBAL_OFFSET_TABLE_+[.-.L12], %ebx
	cmpl	$0, 8(%ebp)
	jne	.L8
	movl	$1, -8(%ebp)
	subl	$12, %esp
	pushl	$1
	call	r_alloca_bytes@PLT
	addl	$16, %esp
	movl	%eax, -12(%ebp)
	cmpl	$0, -12(%ebp)
	je	.L10
	movl	-12(%ebp), %eax
	movb	$0, (%eax)
	jmp	.L10
.L8:
	subl	$12, %esp
	pushl	8(%ebp)
	call	strlen@PLT
	addl	$16, %esp
	incl	%eax
	movl	%eax, -8(%ebp)
	subl	$12, %esp
	pushl	-8(%ebp)
	call	r_alloca_bytes@PLT
	addl	$16, %esp
	movl	%eax, -12(%ebp)
	cmpl	$0, -12(%ebp)
	je	.L10
	subl	$4, %esp
	pushl	-8(%ebp)
	pushl	8(%ebp)
	pushl	-12(%ebp)
	call	memcpy@PLT
	addl	$16, %esp
.L10:
	movl	-12(%ebp), %eax
	movl	-4(%ebp), %ebx
	leave
	ret
	.size	r_alloca_str, .-r_alloca_str
.globl r_alloca_ret_i
	.type	r_alloca_ret_i, @function
r_alloca_ret_i:
	pushl	%ebp
	movl	%esp, %ebp
	subl	$4, %esp
	call	.L15
.L15:
	popl	%ecx
	addl	$_GLOBAL_OFFSET_TABLE_+[.-.L15], %ecx
	cmpl	$0, bufidx@GOTOFF(%ecx)
	jne	.L14
	movl	8(%ebp), %eax
	movl	%eax, -4(%ebp)
	jmp	.L13
.L14:
	decl	bufidx@GOTOFF(%ecx)
	movl	bufidx@GOTOFF(%ecx), %eax
	movl	bufptr@GOTOFF(%ecx,%eax,4), %eax
	movl	%eax, bufnext@GOTOFF(%ecx)
	movl	8(%ebp), %eax
	movl	%eax, -4(%ebp)
.L13:
	movl	-4(%ebp), %eax
	leave
	ret
	.size	r_alloca_ret_i, .-r_alloca_ret_i
	.local	bufptr
	.comm	bufptr,1024,32
	.local	bufmax
	.comm	bufmax,4,4
	.section	.note.GNU-stack,"",@progbits
	.ident	"GCC: (GNU) 3.4.6 (Gentoo 3.4.6, ssp-3.4.5-1.0, pie-8.7.9)"
