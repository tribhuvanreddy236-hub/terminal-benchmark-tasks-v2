SHELL := /bin/bash

BIN_DIR := /app/bin
ANALYZER_BIN := $(BIN_DIR)/analyzer
OUT_DIR := /app/output
REPORT := $(OUT_DIR)/kmemleak_report.json

CARGO ?= cargo
CARGO_FLAGS ?= --release --manifest-path /app/Cargo.toml

.PHONY: all build run clean

all: build

build: $(BIN_DIR)
	$(CARGO) build $(CARGO_FLAGS)
	cp /app/target/release/analyzer $(ANALYZER_BIN)

run: build
	mkdir -p $(OUT_DIR)
	$(ANALYZER_BIN)

clean:
	rm -rf /app/target $(ANALYZER_BIN) $(REPORT)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)
