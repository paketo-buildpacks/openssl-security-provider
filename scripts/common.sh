ROOT=$(realpath "$(dirname "${BASH_SOURCE[0]}")"/../..)

if [[ -d "${ROOT}"/maven-cache && ! -d "${HOME}"/.m2 ]]; then
  ln -s "${ROOT}"/maven-cache "${HOME}"/.m2
fi
