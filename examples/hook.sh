#!/bin/sh
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# hook_command example. Reads one catch JSON on stdin, writes a decision.
# This sample always cancels.
cat >/dev/null
printf '%s\n' '{"decision":"cancel","reason":"sample"}'
