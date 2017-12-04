Fuzzing
=======

Fuzzing faucet with docker
--------------------------

First, get yourself setup with docker based on our :doc:`docker` documentation.

Then you can build and run the afl-fuzz tests:

.. code:: bash

  docker build -t faucet/fuzzer -f dockerfile.fuzz .

  docker run -d \
    -u $(id -u $USER) \
    --name fuzzer \
    -v /var/log/afl/:/var/log/afl/ \
    faucet/fuzzer

AFL then will run indefinitely. You can find the output in /var/log/afl/.
