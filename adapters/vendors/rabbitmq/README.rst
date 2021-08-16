RabbitMQ Adapter for Event Notifications
========================================

This adapter will hook into the Unix socket FAUCET is pushing events to.


Use with Poseidon
^^^^^^^^^^^^^^^^^

See https://github.com/IQTLabs/poseidon for full instructions.

* Poseidon *requires* this adaptor.  Log only parsing is NOT supported.
* Poseidon has its on RabbitMQ server.  Start the adapter, as below, but NOT the RabbitMQ server.
* FA_RABBIT_HOST must be set to an IP address that Poseidon will run as (so the adapter can connect to Poseidon's RabbitMQ server).

To add this plugin using ``docker-compose``, from the top level
directory of FAUCET, export the following additional FAUCET Adapter
environment variables:

::

    FAUCET_EVENT_SOCK       (default is 0, needs to be set to 1)
    FA_RABBIT_HOST          (default is an empty string, and minimally required)
    FA_RABBIT_PORT          (default is 5672)
    FA_RABBIT_EXCHANGE      (default is 'topic_recs')
    FA_RABBIT_EXCHANGE_TYPE (default is 'topic')
    FA_RABBIT_ROUTING_KEY   (default is 'FAUCET.Event')

Then execute:

::

    docker-compose -f docker-compose.yaml \
                   -f adapters/vendors/rabbitmq/docker-compose.yaml \
                   up

Since this requires a connection to a RabbitMQ server there is an
additional ``docker-compose`` file that runs one for convenience and can be
included as follows:

::

    docker-compose -f docker-compose.yaml \
                   -f adapters/vendors/rabbitmq/docker-compose-rabbitmq.yaml \
                   -f adapters/vendors/rabbitmq/docker-compose.yaml \
                   up

Finally, there is an example RabbitMQ consumer that can be used for
testing and development that by default will connect to the above
RabbitMQ server with the default environment variables and with
``FA_RABBIT_HOST=rabbitmq`` set. To start it, after the above command is
up and running, just execute:

::

    pip3 install -r adapters/vendors/rabbitmq/requirements.txt
    python3 adapters/vendors/rabbitmq/example_consumer.py
