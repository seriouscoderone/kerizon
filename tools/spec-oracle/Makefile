ORACLE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
OUTPUT_DIR := $(ORACLE_DIR)output

.PHONY: all test validate generate clean

all: generate

test:
	@echo "=== Running CESR unit tests ==="
	racket $(ORACLE_DIR)cesr/test.rkt

validate: test
	@echo "=== Cross-checking against KERIpy vectors ==="
	cd $(ORACLE_DIR)../.. && racket tools/spec-oracle/validate/cross-check.rkt

generate: validate
	@echo "=== Generating parse-vectors.json ==="
	cd $(ORACLE_DIR)../.. && racket tools/spec-oracle/generate/main.rkt $(OUTPUT_DIR)

clean:
	rm -rf $(OUTPUT_DIR)
