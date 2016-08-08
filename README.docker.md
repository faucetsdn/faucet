## Faucet Dockerfile

This directory contains three docker files: **Dockerfile**,
**Dockerfile.gauge** and **Dockerfile.tests**

### Official builds

We provide official automated builds on Docker Hub so that you can run Faucet
easily without having to build your own.

We use Docker tags to differentiate between versions of Faucet. The latest
tag will always point to the latest git commit. All tagged versions of Faucet
in git are also available to use, for example using the faucet/faucet:v1_0
Docker will run the stable version 1.0 of Faucet.

To pull and run the latest git version of Faucet:

```
docker pull faucet/faucet:latest
docker run -d \
    --name faucet \
    -v <path-to-config-dir>:/etc/ryu/faucet/ \
    -v <path-to-logging-dir>:/var/log/ryu/faucet/ \
    -p 6633:6633 \
    faucet/faucet
```

To pull and run the latest git version of Faucet + Gauge:

```
docker pull faucet/faucet-gauge:latest
docker run -d \
    --name faucet \
    -v <path-to-config-dir>:/etc/ryu/faucet/ \
    -v <path-to-logging-dir>:/var/log/ryu/faucet/ \
    -p 6633:6633 \
    -p 6634:6634 \
    -p 3000:3000 \
    faucet/faucet-gauge
```

### Dockerfile

All that is needed to run faucet.

It can be built as following:
```
docker build -t reannz/faucet .
```
It can be run as following:
```
docker run -d \
    --name faucet \
    -v <path-to-config-dir>:/etc/ryu/faucet/ \
    -v <path-to-logging-dir>:/var/log/ryu/faucet/ \
    -p 6633:6633 \
    reannz/faucet
```

By default it listens on port 6633 for an OpenFlow switch to connect. Faucet
expects to find the configuration file faucet.yaml in the config folder. If
needed the -e option can be used to specify the names of files with the
FAUCET\_LOG, FAUCET\_EXCEPTION\_LOG, FAUCET\_CONFIG environment variables.

### Dockerfile.tests

This runs the mininet tests from the docker entry-point:

```
docker build -t reannz/faucet-tests -f Dockerfile.tests .
apparmor_parser -R /etc/apparmor.d/usr.sbin.tcpdump
sudo docker run --privileged -ti reannz/faucet-tests
```

The apparmor command is currently required on Ubuntu hosts to allow the use of
tcpdump inside the container.

### Dockerfile.gauge

Runs Gauge.

It can be built as following:
```
docker build -t reannz/faucet-gauge -f Dockerfile.gauge .
```
It can be run as following:
```
docker run -d \
    --name gauge \
    -v <path-to-config-dir>:/etc/ryu/faucet/ \
    -v <path-to-logging-dir>:/var/log/ryu/faucet/ \
    -p 6634:6633 \
    reannz/gauge
```
By defualt listens on port 6633. If you are running this with
Faucet you will need to modify the port one of the containers listens on and
configure your switches to talk to both. The faucet
configuration file faucet.yaml should be placed in the config directory, this
also should include to configuration for gauge.

### docker-compose.yaml
This is an example docker-compose file that can be used to set up gauge to talk
to influxdb with a grafana front end.

It can be run with ```docker-compose up```

The database will write to ```/opt/influxdb/shared/data/db```

Grafana First login to grafana using default credentials of
User:admin Password:admin.

Then connect to the influxDB, by adding it as a datasource. Use the following
settings: ``` Name: Gauge # Or whatever you wish Type: InfluxDB 0.9.x Url:
http://127.0.0.1:8086 Access: proxy Http Auth: None Database: faucet User:
faucet # Anything will do Password: faucet # Anything will do ``` Check the
connection using test connection.

From here you can add a new dashboard with and a graph pulling data from the
Gauge datasource.  See the Grafana's documentation for more on how to do this.
