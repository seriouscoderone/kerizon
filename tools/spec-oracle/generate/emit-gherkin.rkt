#lang racket/base

;; Emit Gherkin .feature file from CESR algebraic laws.
;; Each law becomes a Scenario (structural) or Scenario Outline (with Examples).
;; Usage: racket emit-gherkin.rkt <output-dir>

(require racket/list
         racket/file
         "../cesr/laws.rkt"
         "../cesr/tables.rkt"
         "../cesr/counters.rkt")

;; --- Feature header ---

(define (emit-feature-header port)
  (fprintf port "Feature: CESR Algebraic Laws\n")
  (fprintf port "  Specification-derived laws for Composable Event Streaming Representation\n\n"))

;; --- Tags ---

(define (emit-tags port l)
  (fprintf port "  @~a @scope-~a\n" (law-category l) (law-scope l)))

;; --- Examples data ---

(define byte-sequence-lengths '(0 1 2 3 15 16 31 32 57 64))

(define combinatorial-sample
  '(("A" 64) ("D" 32) ("0F" 64) ("0G" 64)))

;; --- Hand-crafted steps per law-id ---

(define (emit-steps port l)
  (case (law-id l)
    ;; === Sizing laws (table-universal) ===
    [(triplet-alignment)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize>\n")
     (fprintf port "    When I compute pad-size\n")
     (fprintf port "    Then (pad-size + raw-size) mod 3 should equal 0\n")]
    [(quad-alignment)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize>\n")
     (fprintf port "    When I compute text-size\n")
     (fprintf port "    Then text-size mod 4 should equal 0\n")]
    [(binary-triplet)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize>\n")
     (fprintf port "    When I compute binary-size\n")
     (fprintf port "    Then binary-size mod 3 should equal 0\n")]
    [(size-ratio)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize>\n")
     (fprintf port "    When I compute text-size and binary-size\n")
     (fprintf port "    Then binary-size * 4 should equal text-size * 3\n")]
    [(pad-bounded)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize>\n")
     (fprintf port "    When I compute pad-size\n")
     (fprintf port "    Then pad-size should be in {0, 1, 2}\n")]
    [(binary-decomposition)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize>\n")
     (fprintf port "    When I compute binary-size and pad-size\n")
     (fprintf port "    Then binary-size should equal pad-size + raw-size\n")]
    ;; === Encoding laws (byte-sequence) ===
    [(base64url-round-trip)
     (fprintf port "    Given a byte sequence of length <length>\n")
     (fprintf port "    When I encode it with base64url and decode the result\n")
     (fprintf port "    Then the decoded bytes should equal the original\n")]
    [(no-padding-chars)
     (fprintf port "    Given a byte sequence of length <length>\n")
     (fprintf port "    When I encode it with base64url\n")
     (fprintf port "    Then the encoded string should not contain \"=\"\n")]
    ;; === Transform laws (table-universal) ===
    [(code-preservation)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize>\n")
     (fprintf port "    When I compute T<-R with arbitrary raw bytes\n")
     (fprintf port "    Then the text should start with \"<code>\"\n")]
    [(text-length-preservation)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize>\n")
     (fprintf port "    When I compute T<-R with arbitrary raw bytes\n")
     (fprintf port "    Then the text length should equal text-size\n")]
    [(binary-length-preservation)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize>\n")
     (fprintf port "    When I compute B<-R with arbitrary raw bytes\n")
     (fprintf port "    Then the binary length should equal binary-size\n")]
    [(transform-composition)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize>\n")
     (fprintf port "    When I compute T<-R and B<-R with the same raw bytes\n")
     (fprintf port "    Then base64url-decode(T<-R) should equal B<-R\n")]
    ;; === Self-framing laws (structural) ===
    [(selector-dispatch)
     (fprintf port "    Given the complete CESR code table\n")
     (fprintf port "    Then every code starting with a character other than \"0\" or \"-\" should have code-size 1\n")
     (fprintf port "    And every code starting with \"0\" should have code-size 2\n")]
    [(code-determines-size)
     (fprintf port "    Given the complete CESR code table\n")
     (fprintf port "    Then each code should map to exactly one unique text-size\n")]
    ;; === Composition laws (combinatorial) ===
    [(stream-concatenation)
     (fprintf port "    Given code1 \"<code1>\" with raw-size <rawSize1> and code2 \"<code2>\" with raw-size <rawSize2>\n")
     (fprintf port "    When I compute T<-R for both and concatenate\n")
     (fprintf port "    Then the combined length should equal text-size1 + text-size2\n")]
    ;; === Counter laws (counter-universal) ===
    [(counter-quad-alignment)
     (fprintf port "    Given counter code \"<code>\"\n")
     (fprintf port "    When I compute counter-text-size\n")
     (fprintf port "    Then counter-text-size mod 4 should equal 0\n")]
    [(counter-binary-triplet)
     (fprintf port "    Given counter code \"<code>\"\n")
     (fprintf port "    When I compute counter-binary-size\n")
     (fprintf port "    Then counter-binary-size mod 3 should equal 0\n")]
    [(counter-size-ratio)
     (fprintf port "    Given counter code \"<code>\"\n")
     (fprintf port "    When I compute counter-text-size and counter-binary-size\n")
     (fprintf port "    Then counter-binary-size * 4 should equal counter-text-size * 3\n")]
    ;; === Counter structural ===
    [(counter-selector-dispatch)
     (fprintf port "    Given the complete counter code table\n")
     (fprintf port "    Then every counter code should start with \"-\" and have code-size 2\n")]
    ;; === Parse laws (table-universal) ===
    [(text-round-trip)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize> and valid raw bytes\n")
     (fprintf port "    When I encode with T<-R and parse back with R<-T\n")
     (fprintf port "    Then both the code and raw should be recovered\n")]
    [(binary-round-trip)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize> and valid raw bytes\n")
     (fprintf port "    When I encode with B<-R and parse back with R<-B\n")
     (fprintf port "    Then both the code and raw should be recovered\n")]
    [(code-extraction)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize> and any raw bytes\n")
     (fprintf port "    When I encode with T<-R and parse back with R<-T\n")
     (fprintf port "    Then the parsed code should equal the original code\n")]
    [(parse-equivalence)
     (fprintf port "    Given code \"<code>\" with raw-size <rawSize> and valid raw bytes\n")
     (fprintf port "    When I parse via R<-T and via R<-B\n")
     (fprintf port "    Then the parsed raw bytes should be identical\n")]
    [else (error 'emit-steps "unknown law: ~a" (law-id l))]))

;; --- Examples tables ---

(define (emit-table-universal-examples port)
  (fprintf port "\n    Examples:\n")
  (fprintf port "      | code | rawSize |\n")
  (for ([entry (all-entries)])
    (fprintf port "      | ~a | ~a |\n"
             (entry-code entry)
             (entry-raw-size entry))))

(define (emit-byte-sequence-examples port)
  (fprintf port "\n    Examples:\n")
  (fprintf port "      | length |\n")
  (for ([len byte-sequence-lengths])
    (fprintf port "      | ~a |\n" len)))

(define (emit-combinatorial-examples port)
  (fprintf port "\n    Examples:\n")
  (fprintf port "      | code1 | rawSize1 | code2 | rawSize2 |\n")
  (for ([pair1 combinatorial-sample])
    (for ([pair2 combinatorial-sample])
      (fprintf port "      | ~a | ~a | ~a | ~a |\n"
               (car pair1) (list-ref pair1 1)
               (car pair2) (list-ref pair2 1)))))

(define (emit-counter-universal-examples port)
  (fprintf port "\n    Examples:\n")
  (fprintf port "      | code |\n")
  (for ([entry (all-counter-entries)])
    (fprintf port "      | ~a |\n" (counter-entry-code entry))))

;; --- Scenario emission ---

(define (emit-scenario port l)
  (emit-tags port l)
  (let ([scope (law-scope l)])
    (cond
      [(memq scope '(table-universal byte-sequence combinatorial counter-universal))
       (fprintf port "  Scenario Outline: ~a\n" (law-name l))
       (fprintf port "    ~a\n" (law-description l))
       (emit-steps port l)
       (case scope
         [(table-universal) (emit-table-universal-examples port)]
         [(byte-sequence) (emit-byte-sequence-examples port)]
         [(combinatorial) (emit-combinatorial-examples port)]
         [(counter-universal) (emit-counter-universal-examples port)])]
      [(eq? scope 'structural)
       (fprintf port "  Scenario: ~a\n" (law-name l))
       (fprintf port "    ~a\n" (law-description l))
       (emit-steps port l)]
      [else (error 'emit-scenario "unknown scope: ~a" scope)])))

;; --- Main ---

(define (emit-gherkin output-dir)
  (make-directory* output-dir)
  (let ([output-path (build-path output-dir "cesr-laws.feature")])
    (call-with-output-file output-path
      (lambda (port)
        (emit-feature-header port)
        (let ([laws (all-laws)])
          (for ([l laws]
                [i (in-naturals)])
            (when (> i 0)
              (fprintf port "\n"))
            (emit-scenario port l))))
      #:exists 'replace)
    (printf "Wrote ~a scenarios to ~a\n" (length (all-laws)) output-path)))

(module+ main
  (let* ([args (current-command-line-arguments)]
         [output-dir (if (> (vector-length args) 0)
                         (vector-ref args 0)
                         "../output")])
    (emit-gherkin output-dir)))
