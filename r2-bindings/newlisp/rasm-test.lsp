#!/usr/bin/newlisp
(load "rasm.lsp")

(define (do-assemble)
	(let (a (RAsm:new))
		(RAsm:set-arch a "x86.nz" 32 0)
		(while (setq ops (read-line))
			(println (RAsm:assemble a ops)))))

(define (do-disassemble)
	(let (a (RAsm:new))
		(RAsm:set-arch a "x86.olly" 32 0)
		(while (setq hex (read-line))
			(println (RAsm:disassemble-hex a hex)))))

(define (show-help)
	(println "Usage: rasm.lsp [-a]ssemble [-d]isassemble")
	(exit))

(if (= (main-args 2) "-a")
	(do-assemble)
	(if (= (main-args 2) "-d")
		(do-disassemble)
		(show-help)))
(exit)
