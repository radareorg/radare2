#!/usr/bin/newlisp
;
; RAsm wrapper for newlisp
;  --pancake'2011

(context 'RAsm)
(if (= ostype "OSX")
	(constant 'SOEXT "dylib")
	(constant 'SOEXT "so")
)
(constant 'RASMLIB (append "/usr/lib/libr_asm." SOEXT))

; from r_asm
(import RASMLIB "r_asm_new")
(import RASMLIB "r_asm_free")
(import RASMLIB "r_asm_use")
(import RASMLIB "r_asm_set_bits")
(import RASMLIB "r_asm_set_big_endian")
(import RASMLIB "r_asm_mdisassemble_hexstr")
(import RASMLIB "r_asm_massemble")
; from r_util
(import RASMLIB "r_list_get_n")
(import RASMLIB "r_list_length")

(define (RAsm:new)
	(r_asm_new)
)

(define (RAsm:set-arch a arch _bits endian)
	(r_asm_use a arch)
	(r_asm_set_bits a _bits)
	(r_asm_set_big_endian a endian)
)

(define (RAsm:disassemble-hex a x)
	(let (acode (r_asm_mdisassemble_hexstr a x))
		(get-string (+ acode 0x50))))

(define (RAsm:assemble a x)
	(let (acode (r_asm_massemble a x))
		(if (= acode 0)
			"" (get-string (+ acode 0x30)))))

(context 'MAIN)
