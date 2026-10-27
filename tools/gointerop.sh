#!/bin/sh
# Builds tools/gointerop (Go's crypto/tls as the other side) offline from the module cache and runs it
# with these arguments; see tools/gointerop/main.go.
#
#	tools/gointerop.sh server cert.pem key.pem 8443
#	tools/gointerop.sh client 8443 roots.pem 2
set -e
dir=$(cd "$(dirname "$0")/gointerop" && pwd)
bin=${TMPDIR:-/tmp}/gointerop.$(id -u)
(cd "$dir" && GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off go build -o "$bin" .)
exec "$bin" "$@"
