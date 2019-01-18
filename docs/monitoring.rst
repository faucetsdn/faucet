Monitoring
==========

Faucet can be monitored in a number of ways. Both the faucet and gauge services
export instrumentation data via a built-in Prometheus exporter which can be
consumed by `Prometheus <https://prometheus.io>`_. By default the Prometheus
exporter is available on port 9302, this can be changed with
:ref:`env-vars` (``FAUCET_PROMETHEUS_PORT`` and ``FAUCET_PROMETHEUS_ADDR``).

Gauge also collects conventional switch statistics (port counters, port state,
etc) and can export these to a number of different databases (including Prometheus).
For information on configuring gauge see the :ref:`gauge-configuration` section.

Prometheus metrics
------------------

Below is a list of the metrics exported by faucet and gauge.

Exported by faucet
~~~~~~~~~~~~~~~~~~

.. include:: autogen/faucet_prometheus_metric_table.rst

Exported by gauge
~~~~~~~~~~~~~~~~~

.. include:: autogen/gauge_prometheus_metric_table.rst
