; Test example in scheme and r_asm api
; pancake@nopcode.org // radare2 @ 2011

(load-extension "/Users/pancake/prg/radare2/r2-bindings/guile/r_asm.dylib" "SWIG_init")
(define asm (new-RAsm))

(define op (new-RAsmAop))
(define (assemble-opcode arch opstr)
	(RAsm-use asm arch)
	(RAsm-assemble asm op opstr)
	(let ((bytes (RAsmAop-get-hex op)))
		(display (string-append "opcode: " opstr))
		(newline)
		(if (equal? bytes "")
			(begin
				(display " * Oops. cannot assemble")
				(newline)
			)
			(begin
				(display (string-append " * bytes:  " bytes))
				(newline)
			)
		)
	)
)

(define arch "x86.olly")
(assemble-opcode arch "invalid opcode")
(assemble-opcode arch "nop")
(assemble-opcode arch "mov eax, 33")
