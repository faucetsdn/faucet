#!/usr/bin/env python3

"""Mininet tests for clib client library functionality.

 * must be run as root
 * you can run a specific test case only, by adding the class name of the test
   case to the command. Eg ./clib_mininet_test.py FaucetUntaggedIPv4RouteTest

It is strongly recommended to run these tests via Docker, to ensure you have
all dependencies correctly installed. See ../docs/.
"""

from clib_mininet_test_main import test_main
import clib_mininet_tests

if __name__ == '__main__':
    test_main([clib_mininet_tests.__name__])
