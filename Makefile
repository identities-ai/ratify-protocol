.PHONY: test-all release release-prepare release-tag release-check

VERSION ?=
PUBLISH ?= 0
GITHUB_RELEASE ?= 0
GOCACHE ?= /tmp/ratify-protocol-go-cache

test-all:
	@GOCACHE="$(GOCACHE)" ./scripts/test-all.sh

release-check:
	@./scripts/check-release-sync.sh

release-prepare:
	@test -n "$(VERSION)" || (echo "usage: make release-prepare VERSION=vX.Y.Z[-tag.N]"; exit 1)
	@GOCACHE="$(GOCACHE)" ./scripts/release.sh prepare "$(VERSION)"

release-tag:
	@test -n "$(VERSION)" || (echo "usage: make release-tag VERSION=vX.Y.Z[-tag.N] [PUBLISH=1] [GITHUB_RELEASE=1]"; exit 1)
	@GOCACHE="$(GOCACHE)" PUBLISH="$(PUBLISH)" GITHUB_RELEASE="$(GITHUB_RELEASE)" ./scripts/release.sh tag "$(VERSION)"

release:
	@echo "The single-step 'make release' was removed — it required a direct push to main."
	@echo "Releases now go through a PR like every other change:"
	@echo "  1. make release-prepare VERSION=vX.Y.Z[-tag.N]   # branch + bump + gate + PR"
	@echo "  2. merge the release PR"
	@echo "  3. make release-tag VERSION=vX.Y.Z[-tag.N]        # tags -> CI publishes"
	@exit 1
