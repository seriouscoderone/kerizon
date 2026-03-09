#lang racket/base

;; Generate deterministic CESR test vectors as JSON.
;; Deterministic seeding: raw bytes = repeat ASCII of first code char to fill raw-size.

(require json
         "../cesr/tables.rkt"
         "../cesr/math.rkt"
         "../cesr/transforms.rkt")

(provide generate-vectors
         generate-vector)

;; Generate deterministic raw bytes for a code entry.
;; Fill raw-size bytes with the ASCII value of the first character of the code.
(define (deterministic-raw entry)
  (let* ([code (entry-code entry)]
         [rs   (entry-raw-size entry)]
         [fill-byte (char->integer (string-ref code 0))])
    (make-bytes rs fill-byte)))

;; Convert bytes to hex string
(define (bytes->hex bs)
  (apply string-append
         (for/list ([b (in-bytes bs)])
           (let ([s (number->string b 16)])
             (if (< b 16)
                 (string-append "0" s)
                 s)))))

;; Generate a single test vector as a hasheq (JSON object).
(define (generate-vector entry)
  (let* ([code (entry-code entry)]
         [desc (entry-description entry)]
         [rs   (entry-raw-size entry)]
         [cat  (entry-category entry)]
         [raw  (deterministic-raw entry)]
         [text (T<-R code raw)]
         [bin  (B<-R code raw)]
         [cs   (code-size code)]
         [ps   (pad-size code rs)]
         [ts   (text-size code rs)]
         [bs   (binary-size code rs)])
    (hasheq 'code code
            'description desc
            'rawHex (bytes->hex raw)
            'rawSize rs
            'text text
            'binaryHex (bytes->hex bin)
            'textLength ts
            'binaryLength bs
            'category cat
            'padSize ps
            'codeSize cs)))

;; Generate all vectors as a JSON-serializable list.
(define (generate-vectors)
  (for/list ([entry (all-entries)])
    (generate-vector entry)))
