#lang racket/base

;; Unit tests for CESR math and transforms.

(require rackunit
         "tables.rkt"
         "math.rkt"
         "transforms.rkt"
         "counters.rkt")

;; ---- Base64url round-trip ----

(test-case "base64url round-trip: no padding chars in output"
  (for ([len '(1 2 3 4 15 16 31 32 57 64)])
    (let* ([raw (make-bytes len (char->integer #\x))]
           [encoded (base64url-encode raw)])
      (check-false (regexp-match? #rx"=" encoded)
                   (format "base64url output contains '=' for len=~a" len))
      (check-equal? (base64url-decode encoded) raw
                    (format "round-trip failed for len=~a" len)))))

(test-case "base64url round-trip: various byte patterns"
  (let* ([raw (list->bytes '(0 1 2 127 128 255))]
         [encoded (base64url-encode raw)]
         [decoded (base64url-decode encoded)])
    (check-equal? decoded raw)))

;; ---- Pad-size correctness ----

(test-case "pad-size: (ps + rs) mod 3 = 0 for all entries"
  (for ([entry (all-entries)])
    (let* ([code (entry-code entry)]
           [rs   (entry-raw-size entry)]
           [ps   (pad-size code rs)]
           [total (+ ps rs)])
      (check-equal? (modulo total 3) 0
                    (format "triplet alignment failed for ~a: ps=~a rs=~a total=~a"
                            code ps rs total)))))

;; ---- Text-size alignment ----

(test-case "text-size: mod 4 = 0 for all entries"
  (for ([entry (all-entries)])
    (let* ([code (entry-code entry)]
           [rs   (entry-raw-size entry)]
           [ts   (text-size code rs)])
      (check-equal? (modulo ts 4) 0
                    (format "text-size mod 4 != 0 for ~a: ts=~a" code ts)))))

;; ---- Binary-size alignment ----

(test-case "binary-size: mod 3 = 0 for all entries"
  (for ([entry (all-entries)])
    (let* ([code (entry-code entry)]
           [rs   (entry-raw-size entry)]
           [bs   (binary-size code rs)])
      (check-equal? (modulo bs 3) 0
                    (format "binary-size mod 3 != 0 for ~a: bs=~a" code bs)))))

;; ---- Spot checks ----

(test-case "spot-check D: rawSize=32, textLength=44, padSize=1, codeSize=1"
  (check-equal? (code-size "D") 1)
  (check-equal? (pad-size "D" 32) 1)    ;; 32%3=2, (3-2)=1
  (check-equal? (text-size "D" 32) 44)  ;; (1+32)*4/3 = 44
  (check-equal? (binary-size "D" 32) 33))

(test-case "spot-check 0B: rawSize=64, textLength=88, padSize=2, codeSize=2"
  (check-equal? (code-size "0B") 2)
  (check-equal? (pad-size "0B" 64) 2)    ;; 64%3=1, (3-1)=2
  (check-equal? (text-size "0B" 64) 88)  ;; (2+64)*4/3 = 88
  (check-equal? (binary-size "0B" 64) 66))

(test-case "spot-check K: rawSize=57, textLength=76, padSize=0"
  (check-equal? (pad-size "K" 57) 0)     ;; 57%3=0
  (check-equal? (text-size "K" 57) 76)   ;; 57*4/3 = 76
  (check-equal? (binary-size "K" 57) 57))

;; ---- T<-R length check ----

(test-case "T<-R output length matches text-size for all entries"
  (for ([entry (all-entries)])
    (let* ([code (entry-code entry)]
           [rs   (entry-raw-size entry)]
           [raw  (make-bytes rs (char->integer (string-ref code 0)))]
           [text (T<-R code raw)]
           [expected-len (text-size code rs)])
      (check-equal? (string-length text) expected-len
                    (format "T<-R length mismatch for ~a: got ~a expected ~a"
                            code (string-length text) expected-len)))))

;; ---- T<-R starts with code ----

(test-case "T<-R output starts with the code string"
  (for ([entry (all-entries)])
    (let* ([code (entry-code entry)]
           [rs   (entry-raw-size entry)]
           [raw  (make-bytes rs 42)]
           [text (T<-R code raw)])
      (check-equal? (substring text 0 (string-length code)) code
                    (format "T<-R doesn't start with code for ~a" code)))))

;; ---- T<-R / B<-R consistency ----

(test-case "T<-R / B<-R consistency: decode(T<-R) = B<-R"
  (for ([entry (all-entries)])
    (let* ([code (entry-code entry)]
           [rs   (entry-raw-size entry)]
           [raw  (make-bytes rs (char->integer (string-ref code 0)))]
           [text (T<-R code raw)]
           [from-text (base64url-decode text)]
           [from-B<-R (B<-R code raw)])
      (check-equal? from-text from-B<-R
                    (format "T<-R/B<-R mismatch for ~a" code)))))

;; ---- Counter sizing ----

(test-case "counter-text-size: mod 4 = 0 for all counter entries"
  (for ([entry (all-counter-entries)])
    (let* ([code (counter-entry-code entry)]
           [ts (counter-text-size code)])
      (check-equal? (modulo ts 4) 0
                    (format "counter-text-size mod 4 != 0 for ~a: ts=~a" code ts)))))

(test-case "counter-binary-size: mod 3 = 0 for all counter entries"
  (for ([entry (all-counter-entries)])
    (let* ([code (counter-entry-code entry)]
           [bs (counter-binary-size code)])
      (check-equal? (modulo bs 3) 0
                    (format "counter-binary-size mod 3 != 0 for ~a: bs=~a" code bs)))))

(test-case "spot-check -A: text-size=4, binary-size=3"
  (check-equal? (counter-text-size "-A") 4)
  (check-equal? (counter-binary-size "-A") 3))

(displayln "All cesr tests passed.")
