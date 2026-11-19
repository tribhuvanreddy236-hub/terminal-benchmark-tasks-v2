RUSTC ?= rustc

all: bin/qrecover

bin/qrecover: src/main.rs src/model.rs src/parse.rs src/recover.rs
	mkdir -p bin
	$(RUSTC) --edition=2021 -C opt-level=2 -C strip=symbols -o $@ src/main.rs

clean:
	rm -f bin/qrecover

.PHONY: all clean
