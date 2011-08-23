#!/usr/bin/newlisp
#
# RBin newLisp Test -- pancake
#
(load "rbin.lsp")


(define (die msg)
	 (println msg)
	 (exit 1)
)

(define (test-rbin file)
	(if (= file nil) (die
		(append "Usage " (main-args 1) " [file]")))
	(println [text]
	=============================
	== RBin test using newlisp ==
	=============================
	[/text])
	(println "File: " file)
	(setq b (RBin:open-file file))
	(define (show-sections b)
		(local (s))
		(setq s (RBin:sections b))
		(dotimes (i (length s))
			(println (format " - SECTION: %d " (s i 0)) (s i 1))
		)
	)
	(show-sections b)

	(println "libs: " (RBin:libraries b))

	(RBin:free b)
)

(test-rbin (main-args 2))
(exit)
