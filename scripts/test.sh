#!/usr/bin/env bash

set -euo pipefail

# shellcheck source=common.sh
source "$(dirname "$0")"/common.sh

cd "${ROOT}"/source

./mvnw clean package
