#!/bin/sh
# Copies the schema from an AssessMatrix checkout and records which commit it
# came from. The schema lives in the AssessMatrix repository; never edit the
# copies under proto/ by hand.
set -eu

src=${AM_REPO:-../AssessMatrix}
if [ ! -d "$src/packages/proto/assessmatrix/v1" ]; then
  echo "no AssessMatrix checkout at $src (set AM_REPO)" >&2
  exit 1
fi

rm -f proto/assessmatrix/v1/*.proto
cp "$src"/packages/proto/assessmatrix/v1/*.proto proto/assessmatrix/v1/
cp "$src"/packages/proto/buf.yaml proto/buf.yaml
git -C "$src" rev-parse HEAD > proto/SOURCE
echo "synced proto/ from $src at $(cat proto/SOURCE)"
