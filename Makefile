# =============================================================================
# p3q — build the C-ABI staticlib for the Go cgo binding
# =============================================================================
#
# The Go precompile `github.com/luxfi/precompile/starkfri` links the
# strict-PQ STARK/FRI verifier through `p3q-c-abi`'s single exported
# entry point `p3q_verify` (see crates/p3q-c-abi/include/lux/p3q.h).
#
# `make staticlib` produces target/release/libp3q_c_abi.a, which the
# cgo `#cgo LDFLAGS` directive in starkfri/verify_cgo.go links against.
# Static linkage (not the dylib) is chosen so a node binary is
# self-contained: no runtime LD_LIBRARY_PATH / DYLD_LIBRARY_PATH.
#
# Usage:
#   make staticlib   # build libp3q_c_abi.a (release)
#   make header      # regenerate include/lux/p3q.h via cbindgen
#   make test        # workspace tests incl. the toy-AIR golden KAT
#   make clean
# =============================================================================

CARGO ?= cargo
RELEASE_DIR := target/release
STATICLIB := $(RELEASE_DIR)/libp3q_c_abi.a

.PHONY: staticlib
staticlib: $(STATICLIB)

$(STATICLIB):
	$(CARGO) build -p p3q-c-abi --release

.PHONY: header
header:
	$(CARGO) build -p p3q-c-abi --release
	@echo "header at crates/p3q-c-abi/include/lux/p3q.h"

.PHONY: test
test:
	$(CARGO) test -p p3q-verifier --features prover
	$(CARGO) test -p p3q-c-abi

# Regenerate the on-disk golden vectors consumed by the Go KAT
# (starkfri/verify_cgo_test.go). Only run when the wire format changes.
.PHONY: vectors
vectors:
	$(CARGO) test -p p3q-verifier --features prover write_golden_vectors -- --ignored --nocapture

.PHONY: clean
clean:
	$(CARGO) clean
