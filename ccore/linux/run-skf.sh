#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec sudo env LD_LIBRARY_PATH="$DIR/lib" "$DIR/skf_test_generic" "$@"
