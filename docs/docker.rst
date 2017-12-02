Docker
======

Faucet Dockerfile
-----------------

This directory contains three docker files: ``Dockerfile``,
``Dockerfile.gauge`` and ``Dockerfile.tests``

Initial configuration
---------------------

.. code:: bash

  sudo mkdir -p /etc/ryu/faucet
  sudo vi /etc/ryu/faucet/faucet.yaml
  sudo vi /etc/ryu/faucet/gauge.yaml

See :doc:`installation` and :doc:`configuration` for configuration options.

In particular, see vendor specific docs for additional files that may be
necessary in /etc/ryu/faucet to configure the switch pipeline.

Official builds
---------------

We provide official automated builds on Docker Hub so that you can run Faucet
easily without having to build your own.

We use Docker tags to differentiate between versions of Faucet. The latest
tag will always point to the latest git commit. All tagged versions of Faucet
in git are also available to use, for example using the faucet/faucet:v1_3
Docker will run the stable version 1.3 of Faucet.


To pull and run the latest git version of Faucet:

.. code:: bash

  mkdir -p /var/log/ryu/faucet/
  docker pull faucet/faucet:latest
  docker run -d \
      --name faucet \
      -v /etc/ryu/faucet/:/etc/ryu/faucet/ \
      -v /var/log/ryu/faucet/:/var/log/ryu/faucet/ \
      -p 6653:6653 \
      -p 9302:9302 \
      faucet/faucet

Port 6653 is used for OpenFlow, port 9302 is used for Prometheus - port 9302 may be omitted if
you do not need Prometheus.

To pull and run the latest git version of Gauge:

.. code:: bash

  mkdir -p /var/log/ryu/gauge/
  docker pull faucet/gauge:latest
  docker run -d \
      --name gauge \
      -v /etc/ryu/faucet/:/etc/ryu/faucet/ \
      -v /var/log/ryu/gauge/:/var/log/ryu/faucet/ \
      -p 6654:6653 \
      -p 9303:9303 \
      faucet/gauge

Port 6654 is used for OpenFlow, port 9303 is used for Prometheus - port 9303 may be omitted if
you do not need Prometheus.

Dockerfile
----------

All that is needed to run faucet.

It can be built as following:

.. code:: bash

  docker build -t faucet/faucet .

It can be run as following:

.. code:: bash

  mkdir -p /var/log/ryu/faucet/
  docker run -d \
      --name faucet \
      -v /etc/ryu/faucet/:/etc/ryu/faucet/ \
      -v /var/log/ryu/faucet/:/var/log/ryu/faucet/ \
      -p 6653:6653 \
      faucet/faucet

By default it listens on port 6653 for an OpenFlow switch to connect. Faucet
expects to find the configuration file faucet.yaml in the config folder. If
needed the -e option can be used to specify the names of files with the
FAUCET\_LOG, FAUCET\_EXCEPTION\_LOG, FAUCET\_CONFIG environment variables.

Dockerfile.gauge
----------------

Runs Gauge.

It can be built as following:

.. code:: bash

  docker build -t faucet/gauge -f Dockerfile.gauge .

It can be run as following:

.. code:: bash

  mkdir -p /var/log/ryu/gauge
  docker run -d \
      --name gauge \
      -v /etc/ryu/faucet/:/etc/ryu/faucet/ \
      -v /var/log/ryu/gauge/:/var/log/ryu/gauge/ \
      -p 6654:6653 \
      faucet/gauge

By default listens on port 6653. If you are running this with
Faucet you will need to modify the port one of the containers listens on and
configure your switches to talk to both. The faucet
configuration file faucet.yaml should be placed in the config directory, this
also should include to configuration for gauge.

docker-compose.yaml
-------------------

This is an example docker-compose file that can be used to set up gauge to talk
to prometheus and influxdb with a grafana instance for dashboards and visualisations.

It can be run with ``docker-compose up``

The time-series databases with the default settings will write to
``/opt/prometheus/`` ``/opt/influxdb/shared/data/db`` you can edit these locations
by modifying the ``docker-compose.yaml`` file.

On OSX, some of the default shared paths are not accessible, so to overwrite
the location that volumes are written to on your host, export an environment
varible name ``FAUCET_PREFIX`` and it will get prepended to the host paths.
For example:

.. code:: bash

  export FAUCET_PREFIX=/opt/faucet

When all the docker containers are running we will need to configure grafana to
talk to prometheus and influxdb. First login to the grafana web interface on
port 3000 (e.g http://localhost:3000) using the default credentials of
``admin:admin``.

Then add two data sources. Use the following settings for prometheus:

::

  Name: Prometheus
  Type: Prometheus
  Url: http://prometheus:9090
  Access: proxy

And the following settings for influxdb:

::

  Name: InfluxDB
  Type: InfluxDB
  Url: http://influxdb:8086
  Access: proxy
  With Credentials: true
  Database: faucet
  User: faucet
  Password: faucet

Check the connection using test connection.

From here you can add a new dashboard and a graphs for pulling data from the
data sources. See the Grafana's documentation for more on how to do this.
