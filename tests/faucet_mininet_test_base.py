#!/usr/bin/python

"""Base class for all FAUCET unit tests."""


import unittest


class FaucetTestBase(unittest.TestCase):
    """Base class for all FAUCET unit tests."""

    ONE_GOOD_PING = '1 packets transmitted, 1 received, 0% packet loss'
    CONFIG = ''
    CONTROLLER_IPV4 = '10.0.0.254'
    CONTROLLER_IPV6 = 'fc00::1:254'
    OFCTL = 'ovs-ofctl -OOpenFlow13'
    CONFIG_GLOBAL = ''
    BOGUS_MAC = '01:02:03:04:05:06'
