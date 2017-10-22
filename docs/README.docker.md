## Faucet Dockerfile

This directory contains three docker files: **Dockerfile**,
**Dockerfile.gauge** and **Dockerfile.tests**

### Initial configuration

```
  sudo mkdir -p /etc/ryu/faucet
  sudo vi /etc/ryu/faucet/faucet.yaml
  sudo vi /etc/ryu/faucet/gauge.yaml
```

See README_install.rst and README_config.rst for configuration options.

** In particular, see vendor specific docs for additional files that may be
necessary in /etc/ryu/faucet to configure the switch pipeline. **

### Official builds

We provide official automated builds on Docker Hub so that you can run Faucet
easily without having to build your own.

We use Docker tags to differentiate between versions of Faucet. The latest
tag will always point to the latest git commit. All tagged versions of Faucet
in git are also available to use, for example using the faucet/faucet:v1_3
Docker will run the stable version 1.3 of Faucet.


To pull and run the latest git version of Faucet:

```
  mkdir -p /var/log/ryu/faucet/
  docker pull faucet/faucet:latest
  docker run -d \
      --name faucet \
      -v /etc/ryu/faucet/:/etc/ryu/faucet/ \
      -v /var/log/ryu/faucet/:/var/log/ryu/faucet/ \
      -p 6653:6653 \
      -p 9302:9302 \
      faucet/faucet
```

Port 6653 is used for OpenFlow, port 9302 is used for Prometheus - port 9302 may be omitted if
you do not need Prometheus.

To pull and run the latest git version of Gauge:

```
  mkdir -p /var/log/ryu/gauge/
  docker pull faucet/gauge:latest
  docker run -d \
      --name gauge \
      -v /etc/ryu/faucet/:/etc/ryu/faucet/ \
      -v /var/log/ryu/gauge/:/var/log/ryu/faucet/ \
      -p 6654:6653 \
      -p 9303:9303 \
      faucet/gauge
```

Port 6654 is used for OpenFlow, port 9303 is used for Prometheus - port 9303 may be omitted if
you do not need Prometheus.

### Dockerfile

All that is needed to run faucet.

It can be built as following:

```
  docker build -t faucet/faucet .
```

It can be run as following:

```
  mkdir -p /var/log/ryu/faucet/
  docker run -d \
      --name faucet \
      -v /etc/ryu/faucet/:/etc/ryu/faucet/ \
      -v /var/log/ryu/faucet/:/var/log/ryu/faucet/ \
      -p 6653:6653 \
      faucet/faucet
```

By default it listens on port 6653 for an OpenFlow switch to connect. Faucet
expects to find the configuration file faucet.yaml in the config folder. If
needed the -e option can be used to specify the names of files with the
FAUCET\_LOG, FAUCET\_EXCEPTION\_LOG, FAUCET\_CONFIG environment variables.

### Dockerfile.tests

This runs the mininet tests from the docker entry-point:

```
  docker build -t faucet/tests -f Dockerfile.tests .
  apparmor_parser -R /etc/apparmor.d/usr.sbin.tcpdump
  modprobe openvswitch
  sudo docker run --privileged -ti faucet/tests
```

The apparmor command is currently required on Ubuntu hosts to allow the use of
tcpdump inside the container.

### Dockerfile.gauge

Runs Gauge.

It can be built as following:

```
  docker build -t faucet/gauge -f Dockerfile.gauge .
```

It can be run as following:

```
  mkdir -p /var/log/ryu/gauge
  docker run -d \
      --name gauge \
      -v /etc/ryu/faucet/:/etc/ryu/faucet/ \
      -v /var/log/ryu/gauge/:/var/log/ryu/gauge/ \
      -p 6654:6653 \
      faucet/gauge
```

By default listens on port 6653. If you are running this with
Faucet you will need to modify the port one of the containers listens on and
configure your switches to talk to both. The faucet
configuration file faucet.yaml should be placed in the config directory, this
also should include to configuration for gauge.

### docker-compose.yaml

This is an example docker-compose file that can be used to set up gauge to talk
to influxdb with a grafana front end.

It can be run with ```docker-compose up```

The database will write to ```/opt/influxdb/shared/data/db```

On OSX, some of the default shared paths are not accessible, so to overwrite
the location that volumes are written to on your host, export an environment
varible name `FAUCET_PREFIX` and it will get prepended to the host paths.
For example:

```
export FAUCET_PREFIX=/opt/faucet
```

Grafana First login to grafana using default credentials of
User:admin Password:admin.

Then connect to the influxDB, by adding it as a datasource. Use the following
settings:

```
  Name: Gauge # Or whatever you wish
  Type: InfluxDB 0.9.x
  Url: http://127.0.0.1:8086
  Access: proxy Http
  Auth: None
  Database: faucet
  User: faucet # Anything will do
  Password: faucet # Anything will do
```

Check the connection using test connection.

From here you can add a new dashboard with and a graph pulling data from the
Gauge datasource.  See the Grafana's documentation for more on how to do this.
