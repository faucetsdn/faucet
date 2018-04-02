#!/usr/bin/env python

"""Mininet tests for FAUCET.

 * must be run as root
 * you can run a specific test case only, by adding the class name of the test
   case to the command. Eg ./faucet_mininet_test.py FaucetUntaggedIPv4RouteTest

It is strongly recommended to run these tests via Docker, to ensure you have
all dependencies correctly installed. See ../docs/.
"""

from clib.mininet_test import test_main

import faucet_mininet_test_unit

if __name__ == '__main__':
    test_main(faucet_mininet_test_unit.__name__)
