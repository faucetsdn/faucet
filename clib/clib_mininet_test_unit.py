"""Mininet tests for clib."""

# pylint: disable=missing-docstring
# pylint: disable=too-many-arguments

import os
import re
import time

from mininet.net import Mininet

import mininet_test_base
import mininet_test_util
import mininet_test_topo

class FaucetSimpleTest(mininet_test_base.FaucetTestBase):
    """Basic untagged VLAN test."""

    N_UNTAGGED = 4
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""

    CONFIG = """
        interface_ranges:
            1-4:
                native_vlan: 100
"""

    def setUp(self):
        super(FaucetSimpleTest, self).setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED,
            links_per_host=self.LINKS_PER_HOST)
        self.start_net()

    def test_ping_all(self):
        """All hosts should have connectivity."""
        self.ping_all_when_learned()
