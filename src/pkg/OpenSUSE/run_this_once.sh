#!/bin/sh
# @author Shivaram Mysore <shivaram.mysore@gmail.com>

# init
function pause() {
  read -p "$*"
}

pip install --upgrade pip
pip install networkx ovs ryu ryu-faucet
pip show ryu-faucet

mkdir -p /var/opt/influxdb
chmod -R 777 /var/opt/influxdb

echo "Writing InfluxDB config file ... /etc/influxdb/influxdb.generated.conf"
/usr/bin/influxd config > /etc/influxdb/influxdb.generated.conf
/usr/bin/grep -n auth-enabled /etc/influxdb/influxdb.generated.conf
echo "Changing [http] auth-enabled value to true from false in the config file"
/usr/bin/sed 's/auth-enabled = false/auth-enabled = true/g' /etc/influxdb/influxdb.generated.conf

echo "Restarting influx service"
systemctl restart influxdb
echo" Checking InfluxDB service status ..."
systemctl status influxdb
echo ""
pause 'Press [Enter] key to continue...'

echo "Checking InfluxDB cURL action ..."
/usr/bin/curl -sl -I localhost:8086/ping
echo "Adding faucet database to influxdb ..."
/usr/bin/curl -G 'http://localhost:8086/query?u=root&p=faucet' --data-urlencode "q=CREATE DATABASE faucet"
echo "Showing all databases ..."
/usr/bin/curl -G 'http://localhost:8086/query?u=root&p=faucet' --data-urlencode 'q=SHOW DATABASES'

echo "Create admin user with password: faucet ..."
pause 'Press [Enter] key to continue...'
/usr/bin/influx  -execute 'CREATE USER "admin" WITH PASSWORD 'faucet' WITH ALL PRIVILEGES'
#/usr/bin/curl -G 'http://localhost:8086/query?u=root&p=faucet' --data-urlencode 'q=CREATE USER "admin" WITH PASSWORD 'faucet' WITH ALL PRIVILEGES'
/usr/bin/influx  -execute 'GRANT ALL PRIVILEGES TO "admin"'
#/usr/bin/curl -G 'http://localhost:8086/query?u=root&p=faucet' --data-urlencode 'q=GRANT ALL PRIVILEGES TO "admin"'
/usr/bin/influx  -execute 

echo "Create grafana user with password: faucet ... used as influxdb datasource login from Grafana"
pause 'Press [Enter] key to continue...'
/usr/bin/influx  -execute 'CREATE USER "grafana" WITH PASSWORD 'faucet''
#/usr/bin/curl -G 'http://localhost:8086/query?u=root&p=faucet' --data-urlencode 'q=CREATE USER "grafana" WITH PASSWORD 'faucet''
/usr/bin/influx  -execute 'GRANT READ ON "faucet" TO "grafana"'
#/usr/bin/curl -G 'http://localhost:8086/query?u=root&p=faucet' --data-urlencode 'q=GRANT READ ON "faucet" TO "grafana"'

echo "Showing all users ..."
/usr/bin/curl -G 'http://localhost:8086/query?u=root&p=faucet' --data-urlencode 'q=SHOW USERS'
echo ""
echo "InfluxDB Web Query Admin UI is accessible via http://localhost:8083"
pause 'Press [Enter] key to continue...'

## Zypper install of grafana on OpenSUSE has problems.  Hence manually install
GRAFANA_PKG_NM=grafana-4.1.2-1486989747.x86_64.rpm
mv /root/pkgs/$GRAFANA_PKG_NM.orig /root/pkgs/$GRAFANA_PKG_NM
/bin/rpm -i --nodeps /root/pkgs/$GRAFANA_PKG_NM
/bin/systemctl daemon-reload
/bin/systemctl enable grafana-server.service

echo "Installing Grafana plugins ..."
grafana-cli plugins install grafana-clock-panel
grafana-cli plugins install grafana-worldmap-panel
grafana-cli plugins install grafana-piechart-panel
grafana-cli plugins install grafana-simple-json-datasource

echo "Starting Grafana Server ..."
systemctl start grafana-server
echo" Checking Grafana Server service status ..."
systemctl status grafana-server
echo ""
echo "Grafana dashboard is available @ http://127.0.0.1:3000/ - use admin/admin for login"
echo ""

echo "NOTE: CouchDB does not work on OpenSUSE.  Install the same on a separate machine"
echo "      or Container and point gauge.yaml to the same http://couchdb.apache.org"
echo "Modify dpid and ports in /etc/ryu/faucet/faucet.yaml"
echo "Update /etc/ryu/faucet/gauge.yaml with correct switch info and credentials"
