# Cargo binary
CARGO = cargo

# zkas compiler binary
ZKAS = zkas

PACKAGE = darkmap

PROOFS_SRC = $(shell find proof -type f -name '*.zk')

PROOFS_BIN = $(PROOFS_SRC:=.bin)

WASM_BIN = darkmap.wasm

all: $(WASM_BIN)

$(WASM_BIN): $(PROOFS_BIN)
	$(CARGO) build --release --package $(PACKAGE) --target wasm32-unknown-unknown
	cp ./target/wasm32-unknown-unknown/release/$(WASM_BIN) $@

client:
	$(CARGO) build --release --features=no-entrypoint,client --package $(PACKAGE)

$(PROOFS_BIN): $(PROOFS_SRC)
	$(ZKAS) $(basename $@) -o $@

clean:
	rm -f $(PROOFS_BIN) $(WASM_BIN)
