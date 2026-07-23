# reveng-recorder — build helpers.
#
# This drives the Rust workspace only (the `reveng-rec` CLI/recorder/GUI and `reveng-viewer`).
# The kernel drivers under driver/ are NOT built here — they need MSBuild + WDK and are signed
# and loaded separately (see driver/*/README.md). Runtime device drivers (USBPcap, reveng-pcidrv)
# are likewise external and never bundled into the exe.

CARGO      ?= cargo
POWERSHELL ?= powershell
APP_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
# Windows MSVC target used for the self-contained build (the default host target on Windows).
WIN_TARGET ?= x86_64-pc-windows-msvc
WIN_RELEASE_DIR = target/$(WIN_TARGET)/release
STANDALONE  = $(WIN_RELEASE_DIR)/reveng-rec.exe
WINDOWS_DIST = target/windows/reveng-recorder-$(APP_VERSION)-windows-x64
WINDOWS_ZIP  = $(WINDOWS_DIST).zip

.DEFAULT_GOAL := help

.PHONY: help build release test standalone windows-release windows-zip viewer run fmt clippy clean

help:
	@echo "reveng-recorder targets:"
	@echo "  build       debug build the workspace"
	@echo "  release     release build the workspace"
	@echo "  test        run the workspace tests (~36)"
	@echo "  standalone  self-contained Windows reveng-rec.exe (static CRT, no VC++ redist)"
	@echo "  windows-zip self-contained Windows user-mode binaries as a .zip"
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

windows-release: export RUSTFLAGS = -C target-feature=+crt-static
windows-release:
	$(CARGO) build --workspace --release --bins --target $(WIN_TARGET)

windows-zip: windows-release
	$(POWERSHELL) -NoProfile -ExecutionPolicy Bypass -Command "if (Test-Path '$(WINDOWS_DIST)') { Remove-Item -Recurse -Force '$(WINDOWS_DIST)' }; New-Item -ItemType Directory -Force -Path '$(WINDOWS_DIST)' | Out-Null; Copy-Item '$(WIN_RELEASE_DIR)/reveng-rec.exe' '$(WINDOWS_DIST)/reveng-rec.exe'; Copy-Item '$(WIN_RELEASE_DIR)/reveng-viewer.exe' '$(WINDOWS_DIST)/reveng-viewer.exe'; Copy-Item 'README.md' '$(WINDOWS_DIST)/README.md'; Copy-Item 'scripts/get-usbpcap.ps1' '$(WINDOWS_DIST)/get-usbpcap.ps1'; if (Test-Path '$(WINDOWS_ZIP)') { Remove-Item -Force '$(WINDOWS_ZIP)' }; Compress-Archive -Path '$(WINDOWS_DIST)/*' -DestinationPath '$(WINDOWS_ZIP)' -Force"
	@echo "windows zip -> $(WINDOWS_ZIP)"

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
