#!/bin/sh
# @author Shivaram Mysore <shivaram.mysore@gmail.com>
mkdir -p /var/opt/influxdb
chmod -R 777 /var/opt/influxdb

zypper install grafana

echo" Checking InfluxDB service status ..."
systemctl status influxdb
echo" Checking Grafana Server service status ..."
systemctl status grafana-server
echo "Command to start Grafana:"
echo "systemctl start grafana-server"

echo "Showing all network interfaces that are up ..."
ip link ls up
echo "Modify dpid, IP address and hostname in files accordingly:"
echo "1.  /etc/ryu/faucet/faucet.yaml"
echo "2.  /etc/ryu/faucet/gauge.yaml"

echo "Adding faucet database to influxdb ..."
echo "run commands:"
echo "# influx"
echo "   Connected to http://localhost:8086 version 0.9"
echo "> create database faucet"
echo "> show databases"
echo "> use faucet"
echo "  Using database faucet"
echo "> show measurements"
echo "> show series"
echo "> exit"

#curl -X POST 'http://localhost:8086/db?u=root&p=faucet' -d '{"name": "faucet"}'
echo ""
echo "Grafana dashboard is available @ http://127.0.0.1:3000/ - use admin/admin for login"

echo ""
echo "CouchDB needs to be installed on a different container or machine."
echo "CouchDB installation: http://couchdb.apache.org"

echo "Change hostname to gauge"
echo "Edit files /etc/localhost, /etc/HOSTNAME and /etc/hostname"
echo "In the above files, uncomment line gauge and comment out line faucet"

