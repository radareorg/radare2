#!/bin/sh

set -e

WORKFLOWS="build.yml ci.yml"
DESTDIR="dist/artifacts"
LIMIT=100

if ! command -v gh &> /dev/null; then
    echo "GitHub CLI (gh command) could not be found"
    exit 1
fi

cd `dirname $PWD/$0`/..

COMMIT="$1" # Optional
if [ -z "${COMMIT}" ]; then
  COMMIT=`git rev-parse HEAD`
  echo "Detected commit: ${COMMIT}"
fi

echo "Removing old dist artifacts..."
rm -Rf "${DESTDIR}"

for WORKFLOW in $WORKFLOWS; do
  echo "Looking for ${COMMIT} in ${WORKFLOW} last ${LIMIT} executions..."
  RUN_ID=`gh run list --workflow "${WORKFLOW}" --limit "${LIMIT}" --json "databaseId,headSha" --jq '.[] | select(.headSha=="'"${COMMIT}"'") | .databaseId'`
  if [ -n "${RUN_ID}" ]; then
    echo "Found run id ${RUN_ID} for ${WORKFLOW} workflow."
    echo "Downloading all artifacts..."
    gh run download "${RUN_ID}" --dir "${DESTDIR}"
  else
    echo "No execution found for ${COMMIT} in the last ${LIMIT} executions of ${WORKFLOW} workflow."
    exit 1
  fi
done

echo "Artifacts downloaded:"
find "${DESTDIR}" -type f
