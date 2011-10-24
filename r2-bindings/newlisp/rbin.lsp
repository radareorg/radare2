#!/usr/bin/newlisp
;
; RBin wrapper for newlisp
;  --pancake'2011

(context 'Rbin)
(if (= ostype "OSX")
	(set 'RBINLIB "/usr/lib/libr_bin.dylib")
	(set 'RBINLIB "/usr/lib/libr_bin.so")
)
; from r_bin
(import RBINLIB "r_bin_new")
(import RBINLIB "r_bin_free")
(import RBINLIB "r_bin_load")
(import RBINLIB "r_bin_get_baddr")
(import RBINLIB "r_bin_list_archs")
(import RBINLIB "r_bin_get_libs")
(import RBINLIB "r_bin_get_imports")
(import RBINLIB "r_bin_get_sections")
; from r_util
(import RBINLIB "r_list_get_n")
(import RBINLIB "r_list_length")

(define (RBin:open-file file)
	(local (b))
	(setq b (r_bin_new))
	(setq ret (r_bin_load b file nil))
	; (if (= ret 0) (die "Cannot open binary"))
	; not calling this method results into a wrong get_baddr and so on..
	(r_bin_list_archs b)
	b
)

(define (RBin:free b)
	(r_bin_free b))

; (setq b (r_bin_new))
; (setq baddr (r_bin_get_baddr b))
; (println (format "base address is: %08llx" baddr))

(define (RBin:libraries b)
	(local (ret))
	(setq ret '())
	(setq libs (r_bin_get_libs b))
	(dotimes (idx (r_list_length libs))
		(push (list (get-string (r_list_get_n libs idx))) ret -1))
	ret
)

(constant 'NSZ 256) ; name size
(define (RBin:sections b)
	(local (ret))
	(setq ret '())
	(setq sects (r_bin_get_sections b))
	(dotimes (idx (r_list_length sects))
		(local (s size rva offset perm))
		(setq
			s (r_list_get_n sects idx)
			name (get-string s)
			size (get-long (+ s NSZ))
; XXX for 64bits
			vsize (get-long (+ s NSZ 8))
			rva (get-long (+ s NSZ 16))
			offset (get-long (+ s NSZ 24))
			perm (get-long (+ s NSZ 32))
			)
		; (println (format
		;	" - section %02d %20s (offset 0x%llx  size %lld)"
		;	idx name (+ offset rva baddr) vsize))
		(push (list idx name size vsize rva offset perm) ret -1)
	)
	ret
)

(context 'MAIN)
