#!/usr/bin/env bash

set -euo pipefail

# shellcheck source=common.sh
source "$(dirname "$0")"/common.sh

cd "${ROOT}"/source

./mvnw \
  build-helper:parse-version \
  versions:set \
    -DgenerateBackupPoms=false \
    -DnewVersion='${parsedVersion.majorVersion}.${parsedVersion.minorVersion}.${parsedVersion.incrementalVersion}'

VERSION=$(./mvnw help:evaluate -Dexpression=project.version -q -DforceStdout)

git add pom.xml
git \
  -c user.name='Paketo Robot' \
  -c user.email='robot@paketo.io' \
  commit \
  --signoff \
  --message "v${VERSION} Release"

git \
  -c user.name='Paketo Robot' \
  -c user.email='robot@paketo.io' \
  tag \
  "v${VERSION}"

git \
  reset \
  --hard \
  HEAD^1

if [[ "${BUMP}" == "major" ]]; then
  # shellcheck disable=SC2016
  PATTERN='${parsedVersion.nextMajorVersion}.${parsedVersion.minorVersion}.${parsedVersion.incrementalVersion}-SNAPSHOT'
elif [[ "${BUMP}" == "minor" ]]; then
  # shellcheck disable=SC2016
  PATTERN='${parsedVersion.majorVersion}.${parsedVersion.nextMinorVersion}.${parsedVersion.incrementalVersion}-SNAPSHOT'
else
  # shellcheck disable=SC2016
  PATTERN='${parsedVersion.majorVersion}.${parsedVersion.minorVersion}.${parsedVersion.nextIncrementalVersion}-SNAPSHOT'
fi

./mvnw \
  build-helper:parse-version \
  versions:set \
    -DgenerateBackupPoms=false \
    -DnewVersion="${PATTERN}"

VERSION=$(./mvnw help:evaluate -Dexpression=project.version -q -DforceStdout)

git add pom.xml
git \
  -c user.name='Paketo Robot' \
  -c user.email='robot@paketo.io' \
  commit \
  --signoff \
  --message "v${VERSION} Development"
