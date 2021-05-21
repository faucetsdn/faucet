#!/bin/ash

set -euo pipefail

APK="apk -q"
BUILDDEPS="gcc python3-dev musl-dev parallel yaml-dev g++"
TESTDEPS="bitstring pytest wheel virtualenv"
PIP3="pip3 -q --no-cache-dir install --upgrade"
FROOT="/faucet-src"

dir=$(dirname "$0")

${APK} add -U git ${BUILDDEPS}
"${dir}/retrycmd.sh" "${PIP3} ${TESTDEPS}"
"${dir}/retrycmd.sh" "${PIP3} -r ${FROOT}/requirements.txt"
${PIP3} ${FROOT}

if [ "$(uname -m)" = "x86_64" ]; then
  (
  echo "Running unit tests"
  cd "${FROOT}"
  python3 -m unittest discover "tests/unit/faucet/"
  python3 -m unittest discover "tests/unit/gauge/"
  )
else
  echo "Skipping tests on $(uname -m) platform"
fi

pip3 uninstall -y ${TESTDEPS} || exit 1
for i in ${BUILDDEPS} ; do
  ${APK} del "$i" || exit 1
done

# Clean up
rm -r "${FROOT}"

# Smoke test
faucet -V || exit 1

find / -name \*pyc -delete || exit 1
