PWSH ?= pwsh
GO ?= go
PNPM ?= pnpm
.PHONY: build
build:
	$(PWSH) -NoProfile -File scripts/build.ps1 -GoCommand "$(GO)" -PnpmCommand "$(PNPM)"
