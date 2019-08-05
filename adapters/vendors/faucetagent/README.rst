Faucet Agent Adapter for gNMI Configuration
========================================

This adapter will hook into the ``faucet.yaml`` file as well as the Prometheus
port running on Faucet.

To add this plugin using ``docker-compose``, from the top level
directory of FAUCET, export the following additional FAUCET Adapter environment
variables:

::

    FAUCET_CONFIG_STAT_RELOAD (default is 0, needs to be set to 1)

This adapter requires certificates, which you either supply yourself in the
``/opt/faucetagent/certs`` directory, or use the simple helper script
``gencerts.sh`` to generate certificates for you (not recommended for
production). Once the certificates are in place execute:

::

    docker-compose -f docker-compose.yaml \
                   -f adapters/vendors/faucetagent/docker-compose.yaml \
                   up

Finally, there is an example client that can be used to test out ``getting``
and ``setting`` the ``faucet.yaml`` file using the faucetagent adapter.
