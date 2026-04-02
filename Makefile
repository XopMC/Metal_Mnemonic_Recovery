.PHONY: help configure build release clean reconfigure

CMAKE ?= cmake
PRESET ?= macos-metal-release
BUILD_PRESET ?= $(PRESET)
BUILD_DIR ?= out/build/macos-metal-release

help:
	@echo "Targets:"
	@echo "  make configure            Configure the macOS Metal build tree"
	@echo "  make build                Build the macOS Metal preset"
	@echo "  make release              Configure and build in one go"
	@echo "  make clean                Remove the macOS Metal build tree"
	@echo "  make reconfigure          Recreate the macOS Metal build tree"
	@echo ""
	@echo "Variables:"
	@echo "  PRESET=macos-metal-release       CMake configure preset"
	@echo "  BUILD_PRESET=macos-metal-release CMake build preset"

configure:
	$(CMAKE) --preset $(PRESET)

build:
	$(CMAKE) --build --preset $(BUILD_PRESET)

release: configure build

clean:
	rm -rf $(BUILD_DIR)

reconfigure: clean configure
