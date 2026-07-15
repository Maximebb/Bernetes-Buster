#!/usr/bin/env bash
# Profile: red-team — aggressive foothold enumeration (still read-only by default)
# SPDX-License-Identifier: AGPL-3.0-or-later
export BBUSTER_AUDIENCE_FOCUS="red-team"
export BBUSTER_SIDE_EFFECTS=0
warn "Loaded profile: red-team — authorized engagements only; enumeration is read-only"
