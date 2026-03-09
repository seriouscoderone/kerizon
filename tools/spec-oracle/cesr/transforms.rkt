#lang racket/base

;; CESR T<-R and B<-R transforms.
;; T<-R: raw bytes → text (Base64url) representation with code prefix.
;; B<-R: raw bytes → binary (native CESR) representation.

(require racket/string
         "math.rkt")

(provide base64url-encode
         base64url-decode
         T<-R
         B<-R)

;; --- Base64url encoding/decoding ---

;; Standard Base64 alphabet
(define b64-chars
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

;; Base64url alphabet
(define b64url-chars
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

;; Encode bytes to base64url (no padding)
(define (base64url-encode bstr)
  (let* ([bs (if (bytes? bstr) bstr (list->bytes bstr))]
         [len (bytes-length bs)]
         [out '()])
    ;; Process 3 bytes at a time
    (let loop ([i 0] [acc '()])
      (if (>= i len)
          (list->string (reverse acc))
          (let* ([b0 (bytes-ref bs i)]
                 [b1 (if (< (+ i 1) len) (bytes-ref bs (+ i 1)) 0)]
                 [b2 (if (< (+ i 2) len) (bytes-ref bs (+ i 2)) 0)]
                 [n (+ (arithmetic-shift b0 16)
                       (arithmetic-shift b1 8)
                       b2)]
                 [c0 (string-ref b64url-chars (bitwise-and (arithmetic-shift n -18) 63))]
                 [c1 (string-ref b64url-chars (bitwise-and (arithmetic-shift n -12) 63))]
                 [remaining (- len i)])
            (cond
              [(>= remaining 3)
               (let ([c2 (string-ref b64url-chars (bitwise-and (arithmetic-shift n -6) 63))]
                     [c3 (string-ref b64url-chars (bitwise-and n 63))])
                 (loop (+ i 3) (cons c3 (cons c2 (cons c1 (cons c0 acc))))))]
              [(= remaining 2)
               (let ([c2 (string-ref b64url-chars (bitwise-and (arithmetic-shift n -6) 63))])
                 (loop (+ i 3) (cons c2 (cons c1 (cons c0 acc)))))]
              [(= remaining 1)
               (loop (+ i 3) (cons c1 (cons c0 acc)))]))))))

;; Decode base64url string to bytes
(define (base64url-decode str)
  (define (char-val c)
    (let ([pos (string-index b64url-chars c)])
      (if pos pos (error 'base64url-decode "invalid char: ~a" c))))
  (define (string-index s c)
    (let loop ([i 0])
      (cond
        [(>= i (string-length s)) #f]
        [(char=? (string-ref s i) c) i]
        [else (loop (+ i 1))])))
  (let* ([len (string-length str)]
         [out '()])
    (let loop ([i 0] [acc '()])
      (if (>= i len)
          (list->bytes (reverse acc))
          (let* ([remaining (- len i)]
                 [v0 (char-val (string-ref str i))]
                 [v1 (if (< (+ i 1) len) (char-val (string-ref str (+ i 1))) 0)]
                 [v2 (if (< (+ i 2) len) (char-val (string-ref str (+ i 2))) 0)]
                 [v3 (if (< (+ i 3) len) (char-val (string-ref str (+ i 3))) 0)]
                 [n (+ (arithmetic-shift v0 18)
                       (arithmetic-shift v1 12)
                       (arithmetic-shift v2 6)
                       v3)]
                 [b0 (bitwise-and (arithmetic-shift n -16) 255)]
                 [b1 (bitwise-and (arithmetic-shift n -8) 255)]
                 [b2 (bitwise-and n 255)])
            (cond
              [(>= remaining 4)
               (loop (+ i 4) (cons b2 (cons b1 (cons b0 acc))))]
              [(= remaining 3)
               (loop (+ i 4) (cons b1 (cons b0 acc)))]
              [(= remaining 2)
               (loop (+ i 4) (cons b0 acc))]
              [else
               (loop (+ i 4) acc)]))))))

;; --- CESR Transforms ---

;; T<-R: Convert raw bytes to text (Base64url) representation.
;; 1. Prepend pad-size zero bytes to raw
;; 2. Base64url-encode the padded raw
;; 3. Overwrite the first code-size characters with the code string
(define (T<-R code raw-bytes)
  (let* ([cs (code-size code)]
         [ps (pad-size code (bytes-length raw-bytes))]
         ;; Prepend ps zero bytes
         [padded (bytes-append (make-bytes ps 0) raw-bytes)]
         ;; Encode
         [encoded (base64url-encode padded)]
         ;; Overwrite first cs characters with code
         [result (string-append code (substring encoded cs))])
    result))

;; B<-R: Convert raw bytes to binary (native CESR) representation.
;; Decode the text representation back to bytes.
(define (B<-R code raw-bytes)
  (base64url-decode (T<-R code raw-bytes)))
