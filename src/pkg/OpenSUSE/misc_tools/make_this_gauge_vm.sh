#!/bin/sh
# @author Shivaram Mysore <shivaram.mysore@gmail.com>
# init
function pause() {
   read -p "$*"
}

mkdir -p /var/opt/influxdb
chmod -R 777 /var/opt/influxdb

echo "Writing InfluxDB config file ... /etc/influxdb/influxdb.generated.conf"
/usr/bin/influxd config > /etc/influxdb/influxdb.generated.conf
/usr/bin/grep -n auth-enabled /etc/influxdb/influxdb.generated.conf
echo "change [http] auth-enabled value to true from false in the config file"
echo "   and then restart influx service"
systemctl restart influxdb
echo" Checking InfluxDB service status ..."
systemctl status influxdb
echo ""
pause 'Press [Enter] key to continue...'

echo ""
echo "CouchDB needs to be installed on a different container or machine."
echo "CouchDB installation: http://couchdb.apache.org"
echo ""
pause 'Press [Enter] key to continue...'

# Zypper install of grafana on OpenSUSE has problems.  Hence manually install
#zypper install grafana
GRAFANA_PKG_NM=grafana-3.1.1-1470047149.x86_64.rpm
mv /root/pkgs/$GRAFANA_PKG_NM.orig /root/pkgs/$GRAFANA_PKG_NM
/bin/rpm -i --nodeps /root/pkgs/$GRAFANA_PKG_NM

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
pause 'Press [Enter] key to continue...'

echo "Showing all network interfaces that are up ..."
ip link ls up
echo "Modify dpid, IP address and hostname in files accordingly:"
echo "1.  /etc/ryu/faucet/faucet.yaml"
echo "2.  /etc/ryu/faucet/gauge.yaml"
echo ""
echo "3.  Change hostname of the machine to gauge"
echo "    Edit files /etc/localhost, /etc/HOSTNAME and /etc/hostname"
echo "    In the above files, uncomment line gauge and comment out line faucet"
echo ""
