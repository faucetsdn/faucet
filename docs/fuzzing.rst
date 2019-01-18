Fuzzing
=======

Fuzzing faucet config with docker
---------------------------------

First, get yourself setup with docker based on our :ref:`docker-install` documentation.

Then you can build and run the afl-fuzz tests:

.. code:: console

  docker build -t faucet/config-fuzzer -f Dockerfile.fuzz-config .

  docker run -d \
    -u $(id -u $USER) \
    --name config-fuzzer \
    -v /var/log/afl/:/var/log/afl/ \
    faucet/config-fuzzer

AFL then will run indefinitely. You can find the output in /var/log/afl/.
You will then need to run the output configs with faucet to see the error produced.

Fuzzing faucet packet handling with docker
------------------------------------------

Build and run the afl-fuzz tests:

.. code:: console

  docker build -t faucet/packet-fuzzer -f Dockerfile.fuzz-packet .

  docker run -d \
    -u $(id -u $USER) \
    --name packet-fuzzer \
    -v /var/log/afl/:/var/log/afl/ \
    -v /var/log/faucet/:/var/log/faucet/ \
    -p 6653:6653 \
    -p 9302:9302 \
    faucet/packet-fuzzer

AFL will then fuzz the packet handling indefinitely. The afl output can be found in /var/log/afl/.
To check the error produced by an afl crash file use display_packet_crash:

.. code:: console

  python3 tests/fuzzer/display_packet_crash.py /var/log/afl/crashes/X

Where X is the name of the crash file. The output can then be found in the faucet logs (/var/log/faucet/).
