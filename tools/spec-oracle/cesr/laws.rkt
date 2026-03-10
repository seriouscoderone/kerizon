#lang racket/base

;; Algebraic laws that CESR guarantees.
;; Each law is both structured data (for downstream emitters) and executable
;; (verifier returns #t on pass, error string on fail).

(require racket/list
         "tables.rkt"
         "math.rkt"
         "transforms.rkt"
         "counters.rkt"
         "parse.rkt")

(provide law law-id law-category law-name law-description law-scope law-verifier
         law-result law-result-law law-result-outcome
         all-laws run-law run-all-laws laws-by-category)

;; --- Structs ---

(struct law (id category name description scope verifier) #:transparent)
(struct law-result (law outcome) #:transparent)

;; --- Helpers ---

;; Check every table entry against a predicate.
;; pred : entry -> (or/c #t string?)
(define (check-all-entries pred)
  (let loop ([entries (all-entries)])
    (if (null? entries)
        #t
        (let ([result (pred (car entries))])
          (if (eq? result #t)
              (loop (cdr entries))
              result)))))

;; --- Sizing Laws (scope: table-universal) ---

(define sizing-laws
  (list
   (law 'triplet-alignment 'sizing
        "Triplet Alignment"
        "(pad-size + raw-size) mod 3 = 0 for every code table entry"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [rs (entry-raw-size entry)]
                    [ps (pad-size code rs)])
               (if (= (modulo (+ ps rs) 3) 0) #t
                   (format "~a: (ps=~a + rs=~a) mod 3 = ~a"
                           code ps rs (modulo (+ ps rs) 3))))))))

   (law 'quad-alignment 'sizing
        "Quad Alignment"
        "text-size mod 4 = 0 for every code table entry"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [rs (entry-raw-size entry)]
                    [ts (text-size code rs)])
               (if (= (modulo ts 4) 0) #t
                   (format "~a: text-size=~a mod 4 = ~a"
                           code ts (modulo ts 4))))))))

   (law 'binary-triplet 'sizing
        "Binary Triplet"
        "binary-size mod 3 = 0 for every code table entry"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [rs (entry-raw-size entry)]
                    [bs (binary-size code rs)])
               (if (= (modulo bs 3) 0) #t
                   (format "~a: binary-size=~a mod 3 = ~a"
                           code bs (modulo bs 3))))))))

   (law 'size-ratio 'sizing
        "Size Ratio"
        "binary-size * 4 = text-size * 3 for every code table entry"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [rs (entry-raw-size entry)]
                    [ts (text-size code rs)]
                    [bs (binary-size code rs)])
               (if (= (* bs 4) (* ts 3)) #t
                   (format "~a: bs*4=~a != ts*3=~a"
                           code (* bs 4) (* ts 3))))))))

   (law 'pad-bounded 'sizing
        "Pad Bounded"
        "pad-size is in {0, 1, 2} for every code table entry"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [rs (entry-raw-size entry)]
                    [ps (pad-size code rs)])
               (if (member ps '(0 1 2)) #t
                   (format "~a: pad-size=~a not in {0,1,2}"
                           code ps)))))))

   (law 'binary-decomposition 'sizing
        "Binary Decomposition"
        "binary-size = pad-size + raw-size for every code table entry"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [rs (entry-raw-size entry)]
                    [ps (pad-size code rs)]
                    [bs (binary-size code rs)])
               (if (= bs (+ ps rs)) #t
                   (format "~a: binary-size=~a != pad=~a + raw=~a"
                           code bs ps rs)))))))))

;; --- Encoding Laws (scope: byte-sequence) ---

(define encoding-laws
  (list
   (law 'base64url-round-trip 'encoding
        "Base64url Round-Trip"
        "decode(encode(raw)) = raw for byte sequences of length 0 through 100"
        'byte-sequence
        (lambda ()
          (let loop ([len 0])
            (if (> len 100)
                #t
                (let* ([raw (make-bytes len (modulo len 256))]
                       [encoded (base64url-encode raw)]
                       [decoded (base64url-decode encoded)])
                  (if (equal? decoded raw)
                      (loop (+ len 1))
                      (format "round-trip failed for len=~a" len)))))))

   (law 'no-padding-chars 'encoding
        "No Padding Characters"
        "base64url-encode(raw) never contains '=' for any input length 0 through 100"
        'byte-sequence
        (lambda ()
          (let loop ([len 0])
            (if (> len 100)
                #t
                (let* ([raw (make-bytes len (modulo len 256))]
                       [encoded (base64url-encode raw)])
                  (if (not (regexp-match? #rx"=" encoded))
                      (loop (+ len 1))
                      (format "padding char found for len=~a: ~a"
                              len encoded)))))))))

;; --- Transform Laws (scope: table-universal) ---

(define transform-laws
  (list
   (law 'code-preservation 'transform
        "Code Preservation"
        "T<-R(code, raw) starts with code for every code table entry"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [rs (entry-raw-size entry)]
                    [raw (make-bytes rs 42)]
                    [text (T<-R code raw)]
                    [cs (string-length code)])
               (if (equal? (substring text 0 cs) code) #t
                   (format "~a: T<-R starts with ~a, expected ~a"
                           code (substring text 0 cs) code)))))))

   (law 'text-length-preservation 'transform
        "Text Length Preservation"
        "string-length(T<-R(code, raw)) = text-size for every code table entry"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [rs (entry-raw-size entry)]
                    [raw (make-bytes rs 42)]
                    [text (T<-R code raw)]
                    [expected (text-size code rs)])
               (if (= (string-length text) expected) #t
                   (format "~a: T<-R len=~a expected=~a"
                           code (string-length text) expected)))))))

   (law 'binary-length-preservation 'transform
        "Binary Length Preservation"
        "bytes-length(B<-R(code, raw)) = binary-size for every code table entry"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [rs (entry-raw-size entry)]
                    [raw (make-bytes rs 42)]
                    [bin (B<-R code raw)]
                    [expected (binary-size code rs)])
               (if (= (bytes-length bin) expected) #t
                   (format "~a: B<-R len=~a expected=~a"
                           code (bytes-length bin) expected)))))))

   (law 'transform-composition 'transform
        "Transform Composition"
        "base64url-decode(T<-R(code, raw)) = B<-R(code, raw) for every code table entry"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [rs (entry-raw-size entry)]
                    [raw (make-bytes rs 42)]
                    [text (T<-R code raw)]
                    [from-text (base64url-decode text)]
                    [from-bin (B<-R code raw)])
               (if (equal? from-text from-bin) #t
                   (format "~a: decode(T<-R) != B<-R" code)))))))))

;; --- Self-Framing Laws (scope: structural) ---

(define self-framing-laws
  (list
   (law 'selector-dispatch 'self-framing
        "Selector Dispatch"
        "First character determines code-size class: not '0' or '-' implies cs=1, '0' implies cs=2"
        'structural
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [first-char (string-ref code 0)]
                    [cs (string-length code)]
                    [expected-cs (cond
                                   [(char=? first-char #\0) 2]
                                   [(char=? first-char #\-) 2]
                                   [else 1])])
               (if (= cs expected-cs) #t
                   (format "~a: first-char=~a cs=~a expected=~a"
                           code first-char cs expected-cs)))))))

   (law 'code-determines-size 'self-framing
        "Code Determines Size"
        "Each code uniquely maps to exactly one text-size"
        'structural
        (lambda ()
          (let loop ([entries (all-entries)] [seen '()])
            (if (null? entries)
                #t
                (let* ([entry (car entries)]
                       [code (entry-code entry)]
                       [rs (entry-raw-size entry)]
                       [ts (text-size code rs)]
                       [existing (assoc code seen)])
                  (if (and existing (not (= (cdr existing) ts)))
                      (format "~a: maps to both ~a and ~a"
                              code (cdr existing) ts)
                      (loop (cdr entries)
                            (if existing seen
                                (cons (cons code ts) seen)))))))))))

;; --- Composition Laws (scope: combinatorial) ---

(define composition-laws
  (list
   (law 'stream-concatenation 'composition
        "Stream Concatenation"
        "T<-R(c1,r1) ++ T<-R(c2,r2) has length ts1 + ts2 for all pairs from a 4-entry sample"
        'combinatorial
        (lambda ()
          (let* ([entries (all-entries)]
                 [sample (list (list-ref entries 0)                     ;; A  (1-char, rs=64)
                               (list-ref entries 3)                     ;; D  (1-char, rs=32)
                               (list-ref entries (- (length entries) 2)) ;; 0F (2-char, rs=64)
                               (list-ref entries (- (length entries) 1)))]) ;; 0G (2-char, rs=64)
            (let outer ([es1 sample])
              (if (null? es1)
                  #t
                  (let inner ([es2 sample])
                    (if (null? es2)
                        (outer (cdr es1))
                        (let* ([e1 (car es1)]
                               [e2 (car es2)]
                               [c1 (entry-code e1)] [rs1 (entry-raw-size e1)]
                               [c2 (entry-code e2)] [rs2 (entry-raw-size e2)]
                               [raw1 (make-bytes rs1 1)]
                               [raw2 (make-bytes rs2 2)]
                               [t1 (T<-R c1 raw1)]
                               [t2 (T<-R c2 raw2)]
                               [combined (string-append t1 t2)]
                               [expected (+ (text-size c1 rs1) (text-size c2 rs2))])
                          (if (= (string-length combined) expected)
                              (inner (cdr es2))
                              (format "~a+~a: combined-len=~a expected=~a"
                                      c1 c2 (string-length combined) expected))))))))))))

;; --- Counter Laws ---

(define counter-laws
  (list
   (law 'counter-quad-alignment 'counter
        "Counter Quad Alignment"
        "counter-text-size mod 4 = 0 for every counter code"
        'counter-universal
        (lambda ()
          (let loop ([entries (all-counter-entries)])
            (if (null? entries)
                #t
                (let* ([entry (car entries)]
                       [code (counter-entry-code entry)]
                       [ts (counter-text-size code)])
                  (if (= (modulo ts 4) 0)
                      (loop (cdr entries))
                      (format "~a: counter-text-size=~a mod 4 = ~a"
                              code ts (modulo ts 4))))))))

   (law 'counter-binary-triplet 'counter
        "Counter Binary Triplet"
        "counter-binary-size mod 3 = 0 for every counter code"
        'counter-universal
        (lambda ()
          (let loop ([entries (all-counter-entries)])
            (if (null? entries)
                #t
                (let* ([entry (car entries)]
                       [code (counter-entry-code entry)]
                       [bs (counter-binary-size code)])
                  (if (= (modulo bs 3) 0)
                      (loop (cdr entries))
                      (format "~a: counter-binary-size=~a mod 3 = ~a"
                              code bs (modulo bs 3))))))))

   (law 'counter-size-ratio 'counter
        "Counter Size Ratio"
        "counter-binary-size * 4 = counter-text-size * 3 for every counter code"
        'counter-universal
        (lambda ()
          (let loop ([entries (all-counter-entries)])
            (if (null? entries)
                #t
                (let* ([entry (car entries)]
                       [code (counter-entry-code entry)]
                       [ts (counter-text-size code)]
                       [bs (counter-binary-size code)])
                  (if (= (* bs 4) (* ts 3))
                      (loop (cdr entries))
                      (format "~a: bs*4=~a != ts*3=~a"
                              code (* bs 4) (* ts 3))))))))

   (law 'counter-selector-dispatch 'counter
        "Counter Selector Dispatch"
        "Every counter code starts with '-' and has code-size 2"
        'structural
        (lambda ()
          (let loop ([entries (all-counter-entries)])
            (if (null? entries)
                #t
                (let* ([entry (car entries)]
                       [code (counter-entry-code entry)]
                       [first-char (string-ref code 0)]
                       [cs (string-length code)])
                  (cond
                    [(not (char=? first-char #\-))
                     (format "~a: first-char=~a expected='-'" code first-char)]
                    [(not (= cs 2))
                     (format "~a: code-size=~a expected=2" code cs)]
                    [else (loop (cdr entries))]))))))))

;; --- Parse Laws (scope: table-universal) ---

(define parse-laws
  (list
   (law 'text-round-trip 'parse
        "Text Round-Trip"
        "R<-T(T<-R(code, validRaw)) recovers both code and raw for every code table entry"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [raw (valid-raw-for-entry entry 42)]
                    [text (T<-R code raw)]
                    [result (R<-T text)])
               (cond
                 [(not (equal? (parse-result-code result) code))
                  (format "~a: code mismatch: got ~a" code (parse-result-code result))]
                 [(not (equal? (parse-result-raw result) raw))
                  (format "~a: raw mismatch" code)]
                 [else #t]))))))

   (law 'binary-round-trip 'parse
        "Binary Round-Trip"
        "R<-B(B<-R(code, validRaw)) recovers both code and raw for every code table entry"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [raw (valid-raw-for-entry entry 42)]
                    [bin (B<-R code raw)]
                    [result (R<-B bin)])
               (cond
                 [(not (equal? (parse-result-code result) code))
                  (format "~a: code mismatch: got ~a" code (parse-result-code result))]
                 [(not (equal? (parse-result-raw result) raw))
                  (format "~a: raw mismatch" code)]
                 [else #t]))))))

   (law 'code-extraction 'parse
        "Code Extraction"
        "R<-T(T<-R(code, anyRaw)).code = code for every code table entry"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [rs (entry-raw-size entry)]
                    [raw (make-bytes rs 255)]
                    [text (T<-R code raw)]
                    [result (R<-T text)])
               (if (equal? (parse-result-code result) code) #t
                   (format "~a: code extraction failed: got ~a"
                           code (parse-result-code result))))))))

   (law 'parse-equivalence 'parse
        "Parse Equivalence"
        "R<-T(text).raw = R<-B(decode(text)).raw for every code table entry with valid raw"
        'table-universal
        (lambda ()
          (check-all-entries
           (lambda (entry)
             (let* ([code (entry-code entry)]
                    [raw (valid-raw-for-entry entry 42)]
                    [text (T<-R code raw)]
                    [result-t (R<-T text)]
                    [result-b (R<-B (base64url-decode text))])
               (if (equal? (parse-result-raw result-t) (parse-result-raw result-b)) #t
                   (format "~a: parse equivalence failed" code)))))))))

;; --- All Laws ---

(define all-laws-list
  (append sizing-laws encoding-laws transform-laws self-framing-laws composition-laws counter-laws parse-laws))

(define (all-laws) all-laws-list)

;; --- Runners ---

(define (run-law l)
  (law-result l ((law-verifier l))))

(define (run-all-laws)
  (map run-law all-laws-list))

(define (laws-by-category cat)
  (filter (lambda (l) (eq? (law-category l) cat)) all-laws-list))

;; --- Report ---

(define (run-laws-and-report)
  (let* ([results (run-all-laws)]
         [total (length results)]
         [passed (length (filter (lambda (r) (eq? (law-result-outcome r) #t)) results))]
         [failed (- total passed)])
    (for-each
     (lambda (r)
       (let ([l (law-result-law r)]
             [o (law-result-outcome r)])
         (if (eq? o #t)
             (printf "  PASS  ~a (~a)\n" (law-id l) (law-name l))
             (printf "  FAIL  ~a (~a): ~a\n" (law-id l) (law-name l) o))))
     results)
    (printf "\n~a/~a laws passed.\n" passed total)
    (when (> failed 0)
      (exit 1))))

(module+ main
  (displayln "=== CESR Algebraic Laws ===")
  (run-laws-and-report))
