#!/usr/bin/env sh
set -eu

if [ "$#" -lt 1 ]; then
	echo "usage: $0 /path/to/inspircd-source [cmake-build-dir]" >&2
	exit 2
fi

INSPIRCD_SRC=$1
BUILD_DIR=${2:-"$INSPIRCD_SRC/build"}
MODULE_DIR="$INSPIRCD_SRC/modules/clientinfo"
THIS_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ ! -f "$INSPIRCD_SRC/CMakeLists.txt" ] || [ ! -d "$INSPIRCD_SRC/modules" ]; then
	echo "error: '$INSPIRCD_SRC' does not look like an InspIRCd source tree" >&2
	exit 1
fi

mkdir -p "$MODULE_DIR"
cp "$THIS_DIR/src/m_clientinfo.cpp" "$MODULE_DIR/main.cpp"
cp "$THIS_DIR/src/ua_parser.cpp" "$MODULE_DIR/ua_parser.cpp"
cp "$THIS_DIR/src/clientinfo.h" "$MODULE_DIR/clientinfo.h"

cmake -S "$INSPIRCD_SRC" -B "$BUILD_DIR"
cmake --build "$BUILD_DIR" --target m_clientinfo

echo "built: $BUILD_DIR/modules/m_clientinfo.so"
