.PHONY: check/tag-version
check/tag-version:
	@TAG_VERSION=$${TAG#kindasafe-}; \
	CARGO_VERSION=$$(sed -n 's/^version = "\(.*\)"/\1/p' kindasafe/Cargo.toml | head -1); \
	if [ "$$TAG_VERSION" != "$$CARGO_VERSION" ]; then \
		echo "error: tag version ($$TAG_VERSION) does not match kindasafe/Cargo.toml version ($$CARGO_VERSION)"; \
		exit 1; \
	fi; \
	echo "tag version ($$TAG_VERSION) matches kindasafe/Cargo.toml version ($$CARGO_VERSION)"

.PHONY: check/versions-match
check/versions-match:
	@KINDASAFE=$$(sed -n 's/^version = "\(.*\)"/\1/p' kindasafe/Cargo.toml | head -1); \
	KINDASAFE_INIT=$$(sed -n 's/^version = "\(.*\)"/\1/p' kindasafe_init/Cargo.toml | head -1); \
	if [ "$$KINDASAFE" != "$$KINDASAFE_INIT" ]; then \
		echo "error: kindasafe ($$KINDASAFE) != kindasafe_init ($$KINDASAFE_INIT)"; \
		exit 1; \
	fi; \
	echo "kindasafe versions in sync: $$KINDASAFE"
