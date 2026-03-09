#lang racket/base

;; CESR size calculation functions.
;; Implements the fundamental CESR sizing invariants:
;;   text-size mod 4 = 0
;;   binary-size mod 3 = 0
;;
;; In CESR, T<-R works by:
;;   1. Prepend pad-size zero bytes to raw → "padded" (triplet-aligned)
;;   2. base64url-encode padded → text chars
;;   3. Overwrite first code-size chars with the code string
;; The code chars replace leading 'A's (from zero-pad bytes) without
;; changing the total length. pad-size depends only on raw-size.

(provide code-size
         pad-size
         text-size
         binary-size)

;; code-size: number of characters in the code string
(define (code-size code)
  (string-length code))

;; pad-size: number of zero-pad bytes so (ps + rs) mod 3 = 0.
;; The code is NOT part of the pad calculation — it overwrites
;; lead base64 characters after encoding.
(define (pad-size code raw-size)
  (let ([remainder (modulo raw-size 3)])
    (if (= remainder 0) 0 (- 3 remainder))))

;; text-size: length of the text (Base64url) representation.
;; text = (ps + rs) * 4/3  (the code overwrites, doesn't extend)
(define (text-size code raw-size)
  (let* ([ps (pad-size code raw-size)]
         [total (+ ps raw-size)])
    (* (/ total 3) 4)))

;; binary-size: length of the binary (CESR native) representation.
;; binary = text * 3/4 = ps + rs
(define (binary-size code raw-size)
  (let ([ps (pad-size code raw-size)])
    (+ ps raw-size)))
