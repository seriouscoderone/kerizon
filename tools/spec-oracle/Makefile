ORACLE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
OUTPUT_DIR := $(ORACLE_DIR)output
CODEC_PKG_DIR := $(ORACLE_DIR)../../cesr-codec

.PHONY: all test laws validate generate emit-gherkin emit-properties emit-library sync-package test-ts clean

all: emit-gherkin emit-properties emit-library

test:
	@echo "=== Running CESR unit tests ==="
	racket $(ORACLE_DIR)cesr/test.rkt

laws: test
	@echo "=== Checking CESR algebraic laws ==="
	racket $(ORACLE_DIR)cesr/laws.rkt

validate: laws
	@echo "=== Cross-checking against KERIpy vectors ==="
	cd $(ORACLE_DIR)../.. && racket tools/spec-oracle/validate/cross-check.rkt

generate: validate
	@echo "=== Generating parse-vectors.json ==="
	cd $(ORACLE_DIR)../.. && racket tools/spec-oracle/generate/main.rkt $(OUTPUT_DIR)

emit-gherkin: generate
	@echo "=== Generating Gherkin feature file ==="
	racket $(ORACLE_DIR)generate/emit-gherkin.rkt $(OUTPUT_DIR)

emit-properties: generate
	@echo "=== Generating property-based test file ==="
	racket $(ORACLE_DIR)generate/emit-property-tests.rkt $(OUTPUT_DIR)

emit-library: generate
	@echo "=== Generating TypeScript codec library ==="
	racket $(ORACLE_DIR)generate/emit-library.rkt $(OUTPUT_DIR)

sync-package: emit-library
	@echo "=== Syncing codec library to cesr-codec package ==="
	mkdir -p $(CODEC_PKG_DIR)/src
	cp $(OUTPUT_DIR)/cesr-codec.ts $(CODEC_PKG_DIR)/src/codec.ts

test-ts: emit-properties emit-library
	@echo "=== Running emitted TypeScript tests ==="
	cd $(ORACLE_DIR) && npx vitest run

clean:
	rm -rf $(OUTPUT_DIR)
