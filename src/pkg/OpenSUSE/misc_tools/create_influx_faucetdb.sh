#!/bin/sh
# @author Shivaram Mysore <shivaram.mysore@gmail.com>
# init
function pause() {
     read -p "$*"
}

echo "Before you start, in file, /etc/influxdb/influxdb.generated.conf"
/usr/bin/grep -n auth-enabled /etc/influxdb/influxdb.generated.conf
echo "Change [http] auth-enabled value to true from false and restart influx service"
echo ""

pause 'Press [Enter] key to continue...'

echo "Checking InfluxDB cURL action ..."
/usr/bin/curl -sl -I localhost:8086/ping
echo "Adding faucet database to influxdb ..."
/usr/bin/curl -G 'http://localhost:8086/query?u=root&p=faucet' --data-urlencode "q=CREATE DATABASE faucet"
echo "Showing all databases ..."
/usr/bin/curl -G 'http://localhost:8086/query?u=root&p=faucet' --data-urlencode 'q=SHOW DATABASES'

### Commands to manually creating faucet db in Influx
# echo "Adding faucet database to influxdb ..."
# echo "run commands:"
# echo "# influx"
# echo "   Connected to http://localhost:8086 version 0.9"
# echo "> create database faucet"
# echo "> show databases"
# echo "> use faucet"
# echo "  Using database faucet"
# echo "> show measurements"
# echo "> show series"
# echo "> exit"
