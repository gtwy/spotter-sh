#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Minimal harness sketch. Silent mode is the default: precheck exits 0
# and the command runs. In enforce mode, 120 asks a trusted admin and
# 121 is never run. The shim directory is prepended for this process
# only. Do not write it into a login profile.

set -eu

SHIM_DIR="${SPOTTER_SHIM_DIR:-"$HOME/.local/lib/spotter-sh/shims"}"
export SPOTTER_SH_HOST=1
export SPOTTER_SH_MODE="${SPOTTER_SH_MODE:-silent}"
export SPOTTER_SH_HOOK="${SPOTTER_SH_HOOK:-/run/agent/spotter.sock}"
export PATH="$SHIM_DIR:$PATH"

command=${1:-}
if [ -z "$command" ]; then
	echo "usage: wiring.sh <command text>" >&2
	exit 2
fi

set +e
spotter-sh precheck -- "$command"
code=$?
set -e

case "$code" in
0)
	# Allowed, or silent mode logged the would-be verdict.
	exec sh -c "$command"
	;;
120)
	# Approvable catch. Ask a trusted admin out of band.
	# If they approve, rerun this same command with the hook
	# answering {"decision":"proceed"}. Do not rewrite it.
	echo "spotter-sh: exit 120, ask an admin before rerunning the identical command" >&2
	exit 120
	;;
121)
	echo "spotter-sh: exit 121, hard block, not run" >&2
	exit 121
	;;
*)
	echo "spotter-sh: exit $code, command not run" >&2
	exit "$code"
	;;
esac
