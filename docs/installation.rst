Installation
============

We recommend installing faucet with apt for first time users and provide
a :doc:`tutorials/first_time` tutorial which walks you through all the
required steps for setting up faucet and gauge for the first time.

Once installed, see :doc:`configuration` for documentation on how to configure
faucet. Also, see :doc:`vendors/index` for documentation on how to configure
your switch.

More advanced methods of installing faucet are also available here:

  1. :ref:`faucet-apt-install`
  2. :ref:`faucet-docker-install`
  3. :ref:`faucet-pip-install`

.. _faucet-apt-install:

Installation using APT
----------------------

We maintain a apt repo for installing faucet and its dependencies on
Debian-based Linux distributions.

Here is a list of packages we supply:

================= ==========================================================================================================
Package           Description
================= ==========================================================================================================
python3-faucet    Install standalone faucet/gauge python3 library
faucet            Install python3 library, systemd service and default config files
gauge             Install python3 library, systemd service and default config files
faucet-all-in-one Install faucet, gauge, prometheus and grafana. Easy to use and good for testing faucet for the first time.
================= ==========================================================================================================


Installation on Debian/Raspbian/Raspberry Pi OS and Ubuntu
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The apt repo supports the following distro versions:

 * Debian 10+
 * Raspbian 10+
 * Raspberry Pi OS 11+
 * Ubuntu 18.04+

The following architectures are supported for each distro:

 * amd64
 * armhf
 * arm64

.. code:: console

  sudo apt-get install curl gnupg apt-transport-https lsb-release
  sudo mkdir -p /etc/apt/keyrings/
  curl -1sLf https://packagecloud.io/faucetsdn/faucet/gpgkey | sudo gpg --dearmor -o /etc/apt/keyrings/faucet.gpg
  echo "deb [signed-by=/etc/apt/keyrings/faucet.gpg] https://packagecloud.io/faucetsdn/faucet/$(lsb_release -si | awk '{print tolower($0)}')/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/faucet.list
  sudo apt-get update

Then to install all components for a fully functioning system on a single machine:

.. code:: console

  sudo apt-get install faucet-all-in-one

or you can install the individual components:

.. code:: console

  sudo apt-get install faucet
  sudo apt-get install gauge

.. raw:: html

  <a href="https://packagecloud.io/"><img height="46" width="158" alt="Private NPM registry and Maven, RPM, DEB, PyPi and RubyGem Repository · packagecloud" src="https://packagecloud.io/images/packagecloud-badge.png" /></a>

.. _faucet-docker-install:

Installation with Docker
------------------------

We provide official automated builds on `Docker Hub <https://hub.docker.com/r/faucet/>`_ so that you can easily
run Faucet and it's components in a self-contained environment without installing on the main host system.

The docker images support the following architectures:

* amd64
* 386
* arm/v6
* arm/v7
* arm64/v8
* ppc64le
* s390x

.. _docker-install:

Installing docker
~~~~~~~~~~~~~~~~~

We recommend installing Docker Community Edition (CE) according to the official
`docker engine installation guide <https://docs.docker.com/engine/installation>`_.

Configuring dockers
~~~~~~~~~~~~~~~~~~~

First, we need to create some configuration files on our host to mount inside
the docker containers to configure faucet and gauge:

.. code:: console

  sudo mkdir -p /etc/faucet
  sudo vi /etc/faucet/faucet.yaml
  sudo vi /etc/faucet/gauge.yaml

See the :doc:`configuration` section for configuration options.

Starting dockers
~~~~~~~~~~~~~~~~

We use Docker tags to differentiate between versions of Faucet. The latest
tag will always point to the latest stable release of Faucet. All tagged
versions of Faucet in git are also available to use, for example using the
``faucet/faucet:1.8.0`` Docker will run the released version 1.8.0 of Faucet.

By default the Faucet and Gauge images are run as the `faucet` user under
UID 0, GID 0. If you need to change that it can be overridden at runtime with
the Docker flags: ``-e LOCAL_USER_ID`` and ``-e LOCAL_GROUP_ID``.

To pull and run the latest version of Faucet:

.. code:: console

  mkdir -p /var/log/faucet/
  docker pull faucet/faucet:latest
  docker run -d \
      --name faucet \
      --restart=always \
      -v /etc/faucet/:/etc/faucet/ \
      -v /var/log/faucet/:/var/log/faucet/ \
      -p 6653:6653 \
      -p 9302:9302 \
      faucet/faucet

Port 6653 is used for OpenFlow, port 9302 is used for Prometheus - port 9302
may be omitted if you do not need Prometheus.

To pull and run the latest version of Gauge:

.. code:: console

  mkdir -p /var/log/faucet/gauge/
  docker pull faucet/gauge:latest
  docker run -d \
      --name gauge \
      --restart=always \
      -v /etc/faucet/:/etc/faucet/ \
      -v /var/log/faucet/:/var/log/faucet/ \
      -p 6654:6653 \
      -p 9303:9303 \
      faucet/gauge

Port 6654 is used for OpenFlow, port 9303 is used for Prometheus - port 9303
may be omitted if you do not need Prometheus.

Additional arguments
~~~~~~~~~~~~~~~~~~~~

You may wish to run faucet under docker with additional arguments, for example:
setting certificates for an encrypted control channel. This can be done by
overriding the docker entrypoint like so:

.. code:: console

  docker run -d \
      --name faucet \
      --restart=always \
      -v /etc/faucet/:/etc/faucet/ \
      -v /etc/ryu/ssl/:/etc/ryu/ssl/ \
      -v /var/log/faucet/:/var/log/faucet/ \
      -p 6653:6653 \
      -p 9302:9302 \
      faucet/faucet \
      faucet \
      --ctl-privkey /etc/ryu/ssl/ctrlr.key \
      --ctl-cert /etc/ryu/ssl/ctrlr.cert  \
      --ca-certs /etc/ryu/ssl/sw.cert

You can get a list of all additional arguments faucet supports by running:

.. code:: console

  docker run -it faucet/faucet faucet --help

Docker compose
~~~~~~~~~~~~~~

This is an example docker-compose file that can be used to set up gauge to talk
to Prometheus and InfluxDB with a Grafana instance for dashboards and visualisations.

It can be run with:

.. code:: console

  docker-compose pull
  docker-compose up

The time-series databases with the default settings will write to
``/opt/prometheus/`` ``/opt/influxdb/shared/data/db`` you can edit these locations
by modifying the ``docker-compose.yaml`` file.

On OSX, some of the default shared paths are not accessible, so to overwrite
the location that volumes are written to on your host, export an environment
varible name ``FAUCET_PREFIX`` and it will get prepended to the host paths.
For example:

.. code:: bash

  export FAUCET_PREFIX=/opt/faucet

When all the docker containers are running we will need to configure Grafana to
talk to Prometheus and InfluxDB. First login to the Grafana web interface on
port 3000 (e.g http://localhost:3000) using the default credentials of
``admin:admin``.

Then add two data sources. Use the following settings for prometheus:

::

  Name: Prometheus
  Type: Prometheus
  Url: http://prometheus:9090

And the following settings for InfluxDB:

::

  Name: InfluxDB
  Type: InfluxDB
  Url: http://influxdb:8086
  With Credentials: true
  Database: faucet
  User: faucet
  Password: faucet

Check the connection using test connection.

From here you can add a new dashboard and a graphs for pulling data from the
data sources. Hover over the ``+`` button on the left sidebar in the web
interface and click ``Import``.

We will import the following dashboards, just download the following
links and upload them through the grafana dashboard import screen:

* `Instrumentation <_static/grafana-dashboards/faucet_instrumentation.json>`_
* `Inventory <_static/grafana-dashboards/faucet_inventory.json>`_
* `Port Statistics <_static/grafana-dashboards/faucet_port_statistics.json>`_

.. _faucet-pip-install:

Installation with Pip
---------------------

You can install the latest pip package, or you can install directly from git via pip.

Installing faucet
~~~~~~~~~~~~~~~~~

First, ensure python3 is installed:

.. code:: console

  apt-get install python3 python3-pip

Then install the latest stable release of faucet from pypi, via pip:

.. code:: console

  pip3 install faucet

Or, install the latest development code from git, via pip:

.. code:: console

  apt-get install git
  pip3 install git+https://github.com/faucetsdn/faucet.git

Starting faucet manually
~~~~~~~~~~~~~~~~~~~~~~~~

Faucet includes a start up script for starting Faucet and Gauge easily from the
command line.

To run Faucet manually:

.. code:: console

  faucet --verbose

To run Gauge manually:

.. code:: console

  gauge --verbose

There are a number of options that you can supply the start up script for
changing various options such as OpenFlow port and setting up an encrypted
control channel. You can find a list of the additional arguments by running:

.. code:: console

  faucet --help


Starting faucet With systemd
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Systemd can be used to start Faucet and Gauge at boot automatically:

.. code:: console

    $EDITOR /etc/systemd/system/faucet.service
    $EDITOR /etc/systemd/system/gauge.service
    systemctl daemon-reload
    systemctl enable faucet.service
    systemctl enable gauge.service
    systemctl restart faucet
    systemctl restart gauge

``/etc/systemd/system/faucet.service`` should contain:

.. literalinclude:: ../etc/systemd/system/faucet.service
  :language: shell
  :caption: faucet.service
  :name: faucet.service

``/etc/systemd/system/gauge.service`` should contain:

.. literalinclude:: ../etc/systemd/system/gauge.service
  :language: shell
  :caption: gauge.service
  :name: gauge.service
