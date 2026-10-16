#!/usr/bin/env python3
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Minimal harness sketch for Shell Spotter.

Silent mode is the default. Prepend the shim directory to PATH for the
agent shell only, export SPOTTER_SH_HOOK, and run `spotter-sh precheck`
before the command. Exit 120 asks a trusted admin. Exit 121 is never run.
"""

import os
import subprocess
import sys


def spawn_env(shim_dir, hook_socket, mode="silent"):
    env = os.environ.copy()
    env["SPOTTER_SH_HOST"] = "1"
    env["SPOTTER_SH_MODE"] = mode or "silent"
    env["SPOTTER_SH_HOOK"] = hook_socket
    env["PATH"] = shim_dir + os.pathsep + env.get("PATH", "")
    return env


def gate(command, ask_admin, bin="spotter-sh"):
    """Return (run, exit_code). ask_admin sees the original command text."""
    done = subprocess.run([bin, "precheck", "--", command])
    code = done.returncode
    if code == 0:
        return True, 0
    if code == 120:
        return bool(ask_admin(command)), 120
    if code == 121:
        return False, 121
    return False, code


def hook_decision(level, approve, admin_ok):
    if level == "hardblock" and not approve:
        return '{"decision":"cancel","reason":"hard block"}\n'
    if admin_ok:
        return '{"decision":"proceed"}\n'
    return '{"decision":"cancel"}\n'


def main(argv):
    if len(argv) != 2:
        print("usage: wiring.py <command text>", file=sys.stderr)
        return 2
    shim = os.environ.get(
        "SPOTTER_SHIM_DIR",
        os.path.expanduser("~/.local/lib/spotter-sh/shims"),
    )
    env = spawn_env(shim, os.environ.get("SPOTTER_SH_HOOK", "/run/agent/spotter.sock"))
    # This sketch does not execute the command. A real harness would
    # start the agent with `env` and, on an approved 120, rerun the
    # identical command while the hook replies proceed.
    print("PATH=" + env["PATH"])
    print("SPOTTER_SH_MODE=" + env["SPOTTER_SH_MODE"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
