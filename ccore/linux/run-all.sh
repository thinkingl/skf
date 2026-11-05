#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$DIR"
exec sudo ./skf_all ./lib/libskf.so "$@"
