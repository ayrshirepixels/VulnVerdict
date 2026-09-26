#!/bin/sh
# Builds Caddy with the standard modules from source, with its networking and crypto dependencies raised to their
# latest releases, so a scan of the binary shows no fixable critical or high findings. Used by the proxy image and the
# all-in-one image. Usage: caddy-build.sh <caddy version> <output path>
set -eu
version="$1"; out="$2"
mkdir -p /src/caddy && cd /src/caddy
go mod init vulnverdict/caddy >/dev/null 2>&1
cat > main.go <<'GO'
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func main() { caddycmd.Main() }
GO
go get "github.com/caddyserver/caddy/v2@${version}"
go get golang.org/x/crypto@latest golang.org/x/net@latest google.golang.org/grpc@v1.83.2 \
  github.com/klauspost/compress@latest github.com/go-chi/chi/v5@latest
go mod tidy
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$out" .
"$out" version
