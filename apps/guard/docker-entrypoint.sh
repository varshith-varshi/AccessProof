#!/bin/sh
set -eu

# Docker creates a new named volume as root.  Correct its ownership once and
# immediately drop privileges before starting the Guard data plane.
chown accessproof:accessproof /var/lib/accessproof-guard
exec runuser -u accessproof -- "$@"
