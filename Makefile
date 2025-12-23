# =============================================================================
# Makefile - Local CI Checks
# =============================================================================
#
# Run `make ci` before pushing to catch all issues locally.
#
# =============================================================================

.PHONY: ci fmt clippy test doc audit clean

# Run all CI checks locally (mirrors GitHub Actions)
ci: fmt clippy test doc
	@echo "\n✅ All CI checks passed!"

# Check formatting (same as CI)
fmt:
	@echo "\n🔍 Checking formatting..."
	cargo fmt -- --check

# Apply formatting fixes
fmt-fix:
	@echo "\n🔧 Applying formatting..."
	cargo fmt

# Run clippy with warnings as errors (same as CI)
clippy:
	@echo "\n🔍 Running clippy..."
	cargo clippy -- -D warnings

# Run clippy with pedantic warnings (advisory, same as CI)
clippy-pedantic:
	@echo "\n🔍 Running clippy (pedantic)..."
	cargo clippy -- -W clippy::pedantic

# Run all tests
test:
	@echo "\n🧪 Running tests..."
	cargo test

# Run doc tests only
test-doc:
	@echo "\n📚 Running doc tests..."
	cargo test --doc

# Run integration tests (requires KVM/HVF)
test-integration:
	@echo "\n🔬 Running integration tests..."
	cargo test --release -- --ignored

# Build documentation with warnings as errors (same as CI)
doc:
	@echo "\n📖 Building documentation..."
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

# Run security audit (requires cargo-audit: cargo install cargo-audit)
audit:
	@echo "\n🔒 Running security audit..."
	cargo audit

# Full CI including audit (slower, use before release)
ci-full: ci audit
	@echo "\n✅ All CI + security checks passed!"

# Build release
build:
	@echo "\n🔨 Building release..."
	cargo build --release

# Clean build artifacts
clean:
	@echo "\n🧹 Cleaning..."
	cargo clean

# Quick check (fast feedback loop)
check:
	@echo "\n⚡ Quick check..."
	cargo check

# Pre-push hook equivalent
pre-push: fmt clippy test
	@echo "\n✅ Ready to push!"
