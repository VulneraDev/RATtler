#!/bin/sh
set -eu

resource_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_root=$(CDPATH= cd -- "$resource_dir/../../../../../.." && pwd)
export PYTHONPATH="$repository_root/src${PYTHONPATH:+:$PYTHONPATH}"
exec /usr/bin/python3 -m rattler "$@"
