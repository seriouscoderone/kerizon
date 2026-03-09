#lang racket/base

;; CESR code table data as association lists.
;; Each entry: (code description raw-size category)
;; Source: CESR specification code tables.

(provide one-char-table
         two-char-table
         all-entries
         entry-code
         entry-description
         entry-raw-size
         entry-category)

;; Accessors
(define (entry-code e)        (list-ref e 0))
(define (entry-description e) (list-ref e 1))
(define (entry-raw-size e)    (list-ref e 2))
(define (entry-category e)    (list-ref e 3))

;; One-character codes (selector = first char, code-size = 1)
(define one-char-table
  '(("A" "Ed25519 indexed signature both same"        64 "indexed-signature")
    ("B" "Ed25519 indexed signature current only"      64 "indexed-signature")
    ("C" "Ed25519 indexed signature big both same"     64 "indexed-signature")
    ("D" "Ed25519 verification key"                    32 "verification-key")
    ("E" "Blake3-256 digest"                           32 "digest")
    ("F" "Blake2b-256 digest"                          32 "digest")
    ("G" "Blake2s-256 digest"                          32 "digest")
    ("H" "SHA3-256 digest"                             32 "digest")
    ("I" "SHA2-256 digest"                             32 "digest")
    ("J" "Seed of Ed25519 private key"                 32 "seed")
    ("K" "Ed448 verification key"                      57 "verification-key")
    ("L" "X25519 public encryption key"                32 "encryption-key")))

;; Two-character codes (selector = '0', code-size = 2)
(define two-char-table
  '(("0A" "Random salt 128 bit"                       16 "salt")
    ("0B" "Ed25519 signature"                          64 "signature")
    ("0C" "X25519 cipher text"                         24 "cipher")
    ("0D" "Blake3-512 digest"                          64 "digest")
    ("0E" "SHA3-512 digest"                            64 "digest")
    ("0F" "Blake2b-512 digest"                         64 "digest")
    ("0G" "SHA2-512 digest"                            64 "digest")))

;; All entries combined (canonical iteration point)
(define (all-entries)
  (append one-char-table two-char-table))
