#lang racket/base

;; CLI entry point: racket main.rkt <output-dir>
;; Generates parse-vectors.json in the specified output directory.

(require json
         racket/file
         "vectors.rkt")

(define (main)
  (let* ([args (current-command-line-arguments)]
         [output-dir (if (> (vector-length args) 0)
                         (vector-ref args 0)
                         "../output")]
         [output-path (build-path output-dir "parse-vectors.json")]
         [vectors (generate-vectors)]
         [json-str (jsexpr->string vectors)])
    ;; Ensure output directory exists
    (make-directory* output-dir)
    ;; Write JSON with pretty printing
    (call-with-output-file output-path
      (lambda (out)
        (write-json vectors out)
        (newline out))
      #:exists 'replace)
    (printf "Wrote ~a vectors to ~a\n" (length vectors) output-path)))

(main)
