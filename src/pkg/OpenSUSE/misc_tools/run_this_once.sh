#!/bin/sh
# @author Shivaram Mysore <shivaram.mysore@gmail.com>
mkdir -p /var/opt/influxdb
chmod -R 777 /var/opt/influxdb

zypper install grafana
pip install ovs ryu
pip install https://pypi.python.org/packages/f5/f3/a8c4e72b4218be5aa84378eb57d89cfc8153efdb4df998cd2a0c544a878a/ryu-faucet-1.0.tar.gz
pip show ryu_faucet

echo" Checking InfluxDB service status ..."
systemctl status influxdb
echo" Checking Grafana Server service status ..."
systemctl status grafana-server
echo "Command to start Grafana:"
echo "systemctl start grafana-server"

echo "Showing all network interfaces that are up ..."
ip link ls up
echo "Modify IP address in files:"
echo "1.  /etc/ryu/faucet/upstart/faucet"
echo "2.  /etc/ryu/faucet/upstart/gauge"

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
