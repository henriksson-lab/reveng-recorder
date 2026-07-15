# reveng-recorder — build helpers.
#
# This drives the Rust workspace only (the `reveng-rec` CLI/recorder/GUI and `reveng-viewer`).
# The kernel drivers under driver/ are NOT built here — they need MSBuild + WDK and are signed
# and loaded separately (see driver/*/README.md). Runtime device drivers (USBPcap, reveng-pcidrv)
# are likewise external and never bundled into the exe.

CARGO      ?= cargo
# Windows MSVC target used for the self-contained build (the default host target on Windows).
WIN_TARGET ?= x86_64-pc-windows-msvc
STANDALONE  = target/$(WIN_TARGET)/release/reveng-rec.exe

.DEFAULT_GOAL := help

.PHONY: help build release test standalone viewer run fmt clippy clean

help:
	@echo "reveng-recorder targets:"
	@echo "  build       debug build the workspace"
	@echo "  release     release build the workspace"
	@echo "  test        run the workspace tests (~36)"
	@echo "  standalone  self-contained Windows reveng-rec.exe (static CRT, no VC++ redist)"
	@echo "  viewer      release build the reveng-viewer GUI"
	@echo "  run         run reveng-rec         (args:  make run ARGS='record --help')"
	@echo "  fmt         cargo fmt"
	@echo "  clippy      cargo clippy"
	@echo "  clean       cargo clean"
	@echo ""
	@echo "  standalone exe -> $(STANDALONE)"

build:
	$(CARGO) build --workspace

release:
	$(CARGO) build --workspace --release

test:
	$(CARGO) test --workspace

# Self-contained Windows exe: release + statically-linked C runtime (`+crt-static`), so it runs
# on a stock Windows box with no Visual C++ redistributable installed. Windows-only.
standalone: export RUSTFLAGS = -C target-feature=+crt-static
standalone:
	$(CARGO) build --release --bin reveng-rec --target $(WIN_TARGET)
	@echo "standalone exe -> $(STANDALONE)"

viewer:
	$(CARGO) build --release --bin reveng-viewer

run:
	$(CARGO) run --bin reveng-rec -- $(ARGS)

fmt:
	$(CARGO) fmt

clippy:
	$(CARGO) clippy --workspace

clean:
	$(CARGO) clean
