.PHONY: test-all release release-check

VERSION ?=
PUSH ?= 0
PUBLISH ?= 0
GITHUB_RELEASE ?= 0
GOCACHE ?= /tmp/ratify-protocol-go-cache

test-all:
	@GOCACHE="$(GOCACHE)" ./scripts/test-all.sh

release-check:
	@./scripts/check-release-sync.sh

release:
	@test -n "$(VERSION)" || (echo "usage: make release VERSION=vX.Y.Z[-tag.N] [PUSH=1] [PUBLISH=1] [GITHUB_RELEASE=1]"; exit 1)
	@GOCACHE="$(GOCACHE)" PUSH="$(PUSH)" PUBLISH="$(PUBLISH)" GITHUB_RELEASE="$(GITHUB_RELEASE)" ./scripts/release.sh "$(VERSION)"
