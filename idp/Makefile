# Variables
OUTPUT_DIR=bin
CLI_BINARY=idp
GO_ENV=CGO_ENABLED=0
VERSION?=$(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.1")

# All target to build all binaries
all: format clean build

# Format the code
format:
	@echo "Formatting code..."
	@find . -name '*.go' -exec sh -c 'gofmt -w "$$1" && golines -m 120 -w "$$1"' _ {} \;
	@echo "Code formatted"

# Build the server binary
build:
	@echo "Building $(CLI_BINARY)..."
	@mkdir -p $(OUTPUT_DIR)
	@go build -ldflags="-X 'main.version=$(VERSION)'" -o $(OUTPUT_DIR)/$(CLI_BINARY) ./cmd/main.go
	@echo "Built $(OUTPUT_DIR)/$(CLI_BINARY)"

# Clean generated binaries and temporary files
clean:
	@echo "Cleaning binaries..."
	@rm -rf $(OUTPUT_DIR)
	@echo "Removed $(OUTPUT_DIR)"

.PHONY: all format clean build
