#!/bin/bash

echo "{\"url\":\"https://packagecloud.io\",\"token\":\"$PACKAGECLOUD_TOKEN\"}" > ~/.packagecloud

git_tmp_dir=$(mktemp -d /tmp/distro-info-data-XXXXX)

echo "==== Cloning distro-info-data git repo ==="

git clone --depth 1 https://salsa.debian.org/debian/distro-info-data "${git_tmp_dir}"

for release in $(awk -F ',' -v today="$(date --utc "+%F")" \
    'BEGIN {OFS=","} NR>1 { if (($6 == "" || $6 >= today) && ($5 != "" && $5 <= today)) print $3 }' \
    ${git_tmp_dir}/ubuntu.csv); do

    echo "==== Uploading packages to ubuntu/${release} ==="
    package_cloud push faucetsdn/faucet/ubuntu/${release} *.deb < /dev/null || true
done

for release in $(awk -F ',' -v today="$(date --utc "+%F")" \
    'BEGIN {OFS=","} NR>1 { if (($6 == "" || $6 >= today) && ($4 != "" && $4 <= today)) print $3 }' \
    ${git_tmp_dir}/debian.csv | egrep -v "(sid|experimental)"); do

    echo "==== Uploading packages to debian/${release} ==="
    package_cloud push faucetsdn/faucet/debian/$release *.deb < /dev/null || true

    echo "==== Uploading packages to raspbian/${release} ==="
    package_cloud push faucetsdn/faucet/raspbian/$release *.deb < /dev/null || true
done

rm -rf "${git_tmp_dir}"
