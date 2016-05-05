## Faucet Dockerfile

This directory contains two docker files **Dockerfile** and
**Dockerfile.gauge**.

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
    -v <path-to-config-dir>:/etc/opt/faucet/ \
    -v <path-to-logging-dir>:/var/log/faucet/ \
    -p 6633:6633 \
    reannz/faucet
```

By default it listens on port 6633 for an OpenFlow switch to connect. Faucet
expects to find the configuration file faucet.yaml in the config folder. If
needed the -e option can be used to specify the names of files with the
FAUCET\_LOG, FAUCET\_EXCEPTION\_LOG, FAUCET\_CONFIG environment variables.
Logs are written to /config/ for easy access from the host.

### Dockerfile.dev

Intended to build a container with the faucet package built using the **dockerdev** make target. To use it, first run in the top-level directory:

```
make dockerdev
```

Then, build the dev container:

```
docker build -t reannz/faucet-dev -f Dockerfile.dev .
```

Then run it, similar to the **Dockerfile** container:

```
docker run -d \
    --name faucet-dev \
    -v <path-to-config-dir>:/etc/opt/faucet/ \
    -v <path-to-logging-dir>:/var/log/faucet/ \
    -p 6633:6633 \
    reannz/faucet-dev
```

### Dockerfile.tests

Similar to **Dockerfile.dev**, this builds faucet locally, but then runs the mininet tests from the docker entrypoint:

```
make dockerdev
cd docker/
docker build -t reannz/faucet-tests -f Dockerfile.tests .
apparmor_parser -R /etc/apparmor.d/usr.sbin.tcpdump
sudo docker run --privileged -ti reannz/faucet-tests
```

The apparmor command is required on the host to allow the use of tcpdump inside the container.

### Dockerfile.gauge

Includes faucet and gauge, including influxDB and grafana for viewing the
resulting graphs.  Consider this to be an alpha image, it does not store influx
data in a persitant location.

It can be built as following:
```
docker build -t reannz/faucet-gauge -f Dockerfile.gauge .
```
It can be run as following:
```
docker run -d \
    --name faucet \
    -v <path-to-config-dir>:/etc/opt/faucet/ \
    -v <path-to-logging-dir>:/var/log/faucet/ \
    -p 6633:6633 \
    -p 6634:6634 \
    -p 3000:3000 \
    reannz/faucet-gauge
```

By default faucet listens on port 6633 and gauge on port 6634 for an OpenFlow
switch. As such your switches should be configured to talk to both.  The faucet
configuration file faucet.yaml should be placed in the config directory, this
also should include to configuration for guage.

Grafana is exposed on port 3000, and should be accessable over http from a
browser.

#### Configuring Grafana First login to grafana using default credientials of
User:admin Password:admin.

Then connect to the influxDB, by adding it as a datasource. Use the following
settings: ``` Name: Gauge # Or whatever you wish Type: InfluxDB 0.9.x Url:
http://127.0.0.1:8086 Access: proxy Http Auth: None Database: faucet User:
faucet # Anything will do Password: faucet # Anything will do ``` Check the
connection using test connection.

From here you can add a new dashboard with and a graph pulling data from the
Gauge datasource.  See the Grafana's documentation for more on how to do this.
