#!/bin/bash

set -euf -o pipefail
ROOTDIR=$(readlink -f "$(dirname $0)")

find "$ROOTDIR" -type f \( -name "*.c" -o -name "*.h" \) | while read f; do
	clang-format --style=file -i "$f"
done
