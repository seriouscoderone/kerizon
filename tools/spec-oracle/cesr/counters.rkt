#lang racket/base

;; CESR counter code table.
;; Counter codes (selector '-', code-size 2) encode integer counts, not raw bytes.
;; They get their own module and table, separate from Matter codes.

(provide counter-table
         all-counter-entries
         counter-entry-code counter-entry-description
         counter-entry-count-range counter-entry-category
         counter-text-size counter-binary-size)

;; Each entry: (code description count-range category)
(define counter-table
  '(("-A" "Controller indexed signatures count" 4095 "counter")
    ("-B" "Witness indexed signatures count"    4095 "counter")))

;; Accessors
(define (counter-entry-code e)        (list-ref e 0))
(define (counter-entry-description e) (list-ref e 1))
(define (counter-entry-count-range e) (list-ref e 2))
(define (counter-entry-category e)    (list-ref e 3))

(define (all-counter-entries) counter-table)

;; Fixed sizing: 2-char counter → text-size=4, binary-size=3
(define (counter-text-size code)   (* 2 (string-length code)))
(define (counter-binary-size code) (/ (* 3 (counter-text-size code)) 4))
