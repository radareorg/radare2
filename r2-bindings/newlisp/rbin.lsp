#!/usr/bin/newlisp
; 
(set 'RBin "/usr/lib/libr_bin.so")
(import RBin "r_bin_new")
(import RBin "r_bin_load")
(import RBin "r_bin_get_baddr")
(import RBin "r_bin_list_archs")
(import RBin "r_bin_get_libs")
(import RBin "r_bin_get_imports")

(import RBin "r_list_get_n")
(import RBin "r_list_length")

(println [text]
=============================
== RBin test using newlisp ==
=============================
[/text])

(define (die msg)
 (println msg)
 (exit 1)
)

(set 'b (r_bin_new))
(set 'ret (r_bin_load b "/bin/ls" nil))
; (if (= ret 0) (die "Cannot open binary"))
; not calling this method results into a wrong get_baddr and so on..
(r_bin_list_archs b)

(set 'baddr (r_bin_get_baddr b))

(println (format "base address is: %08llx" baddr))

(set 'libs (r_bin_get_libs b))

(dotimes (idx (r_list_length libs))
	(println (format
		"library %d %s" idx
		(get-string (r_list_get_n libs idx))))
)

(exit 0)

; (context 'RBin)
; (context 'MAIN)
