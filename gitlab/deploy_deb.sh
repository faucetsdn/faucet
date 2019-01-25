#!/bin/bash

echo "{\"url\":\"https://packagecloud.io\",\"token\":\"$PACKAGECLOUD_TOKEN\"}" > ~/.packagecloud

curl -o /tmp/ubuntu-releases.csv https://salsa.debian.org/debian/distro-info-data/raw/master/ubuntu.csv
curl -o /tmp/debian-releases.csv https://salsa.debian.org/debian/distro-info-data/raw/master/debian.csv

for release in $(awk -F ',' -v today="$(date --utc "+%F")" \
    'BEGIN {OFS=","} NR>1 { if (($6 == "" || $6 >= today) && ($5 != "" && $5 <= today)) print $3 }' \
    /tmp/ubuntu-releases.csv); do

    package_cloud push faucetsdn/faucet/ubuntu/$release *.deb || true
done

for release in $(awk -F ',' -v today="$(date --utc "+%F")" \
    'BEGIN {OFS=","} NR>1 { if (($6 == "" || $6 >= today) && ($4 != "" && $4 <= today)) print $3 }' \
    /tmp/debian-releases.csv | egrep -v "(sid|experimental)"); do

    package_cloud push faucetsdn/faucet/debian/$release *.deb || true
    package_cloud push faucetsdn/faucet/raspbian/$release *.deb || true
done
