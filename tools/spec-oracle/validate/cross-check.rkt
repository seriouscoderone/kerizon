#lang racket/base

;; Cross-check oracle output against KERIpy reference vectors.
;; Reads keripy-vectors.json and verifies T<-R produces matching text.

(require json
         "../cesr/math.rkt"
         "../cesr/transforms.rkt")

;; Convert hex string to bytes
(define (hex->bytes hex-str)
  (let* ([len (string-length hex-str)]
         [byte-count (/ len 2)])
    (list->bytes
     (for/list ([i (in-range byte-count)])
       (string->number (substring hex-str (* i 2) (+ (* i 2) 2)) 16)))))

(define (run-cross-check)
  (let* ([vectors-path (build-path (current-directory)
                                    "tools" "spec-oracle" "known-good"
                                    "keripy-vectors.json")]
         [vectors (call-with-input-file vectors-path read-json)]
         [total (length vectors)]
         [passed 0]
         [failed 0])
    (printf "Cross-checking ~a KERIpy reference vectors...\n" total)
    (for ([v vectors])
      (let* ([code (hash-ref v 'code)]
             [raw-hex (hash-ref v 'rawHex)]
             [expected-text (hash-ref v 'text)]
             [raw (hex->bytes raw-hex)]
             [actual-text (T<-R code raw)])
        (if (string=? actual-text expected-text)
            (begin
              (printf "  PASS: ~a (~a)\n" code (hash-ref v 'description ""))
              (set! passed (+ passed 1)))
            (begin
              (printf "  FAIL: ~a\n    expected: ~a\n    actual:   ~a\n"
                      code expected-text actual-text)
              (set! failed (+ failed 1))))))
    (printf "\nResults: ~a passed, ~a failed out of ~a\n" passed failed total)
    (when (> failed 0)
      (exit 1))))

(run-cross-check)
