#lang racket/base

;; CESR R<-T and R<-B parse (reverse) transforms.
;; R<-T: text (Base64url) representation → code + raw bytes.
;; R<-B: binary (native CESR) representation → code + raw bytes.
;; Also: lead-byte constraint helpers for round-trip validity.

(require "tables.rkt"
         "math.rkt"
         "transforms.rkt")

(provide parse-result parse-result-code parse-result-raw
         selector-dispatch
         R<-T R<-B
         lead-constrained-bits
         valid-raw-for-entry
         code-lookup)

;; --- Parse result struct ---

(struct parse-result (code raw) #:transparent)

;; --- Code lookup ---

(define code-lookup-table
  (let ([ht (make-hash)])
    (for ([entry (all-entries)])
      (hash-set! ht (entry-code entry) entry))
    ht))

(define (code-lookup code)
  (hash-ref code-lookup-table code
            (lambda () (error 'code-lookup "unknown code: ~a" code))))

;; --- Selector dispatch ---

;; Given the first character of a CESR text primitive, return the code-size.
(define (selector-dispatch ch)
  (cond
    [(char=? ch #\0) 2]
    [(char=? ch #\-) 2]
    [else 1]))

;; --- R<-T: Text → (code, raw) ---

;; Parse a CESR text representation back into code and raw bytes.
;; Algorithm (matches KERIpy Matter._exfil):
;;   1. Determine code-size from first character
;;   2. Extract code string
;;   3. Look up raw-size from code table
;;   4. Replace first cs chars with 'A' (base64url zero)
;;   5. Decode restored base64url → padded bytes
;;   6. Strip pad-size leading bytes → raw
(define (R<-T text)
  (let* ([cs (selector-dispatch (string-ref text 0))]
         [code (substring text 0 cs)]
         [entry (code-lookup code)]
         [rs (entry-raw-size entry)]
         [ps (pad-size code rs)]
         ;; Restore first cs characters to 'A'
         [restored (string-append (make-string cs #\A) (substring text cs))]
         ;; Decode base64url
         [padded (base64url-decode restored)]
         ;; Strip padding bytes
         [raw (subbytes padded ps)])
    (parse-result code raw)))

;; --- R<-B: Binary → (code, raw) ---

;; Parse a CESR binary representation back into code and raw bytes.
;; Binary is just decode(text), so: encode back to text, then R<-T.
(define (R<-B binary)
  (R<-T (base64url-encode binary)))

;; --- Lead-byte constraint ---

;; When code-size > pad-size, the code overwrite bleeds into raw-data bits.
;; Those leading bits must be zero for lossless round-trip.
;; Returns the number of constrained leading bits (0, 6, or 12).
(define (lead-constrained-bits code raw-size)
  (let* ([cs (code-size code)]
         [ps (pad-size code raw-size)])
    (if (> cs ps)
        (* (- cs ps) 6)
        0)))

;; --- Valid raw for entry ---

;; Generate raw bytes for a code table entry with constrained leading bits zeroed.
;; fill-byte: value to fill non-constrained bytes with.
(define (valid-raw-for-entry entry fill-byte)
  (let* ([code (entry-code entry)]
         [rs (entry-raw-size entry)]
         [raw (make-bytes rs fill-byte)]
         [lcb (lead-constrained-bits code rs)])
    (when (> lcb 0)
      (let* ([full-bytes (quotient lcb 8)]
             [remaining-bits (modulo lcb 8)])
        (for ([i (in-range full-bytes)])
          (bytes-set! raw i 0))
        (when (> remaining-bits 0)
          (let ([mask (sub1 (arithmetic-shift 1 (- 8 remaining-bits)))])
            (bytes-set! raw full-bytes
                        (bitwise-and (bytes-ref raw full-bytes) mask))))))
    raw))
