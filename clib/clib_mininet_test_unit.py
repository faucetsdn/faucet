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

from tcpdump_helper import TcpdumpHelper

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


class FaucetTcpdumpHelperTest(FaucetSimpleTest):
    """Test for TcpdumpHelper class"""

    def test_tcpdump_execute(self):
        """Check tcpdump filter monitors ping"""
        self.ping_all_when_learned()
        from_host = self.net.hosts[0]
        to_host = self.net.hosts[1]
        tcpdump_filter = ('icmp')
        tcpdump_helper = TcpdumpHelper(to_host, tcpdump_filter, [
                lambda: from_host.cmd('ping -c1 %s' % to_host.IP())])
        tcpdump_txt = tcpdump_helper.execute()
        self.assertTrue(re.search(
            '%s: ICMP echo request' % to_host.IP(), tcpdump_txt))

    def test_tcpdump_nextline(self):
        """Check tcpdump filter monitors ping using next_line"""
        self.ping_all_when_learned()
        from_host = self.net.hosts[0]
        to_host = self.net.hosts[1]
        tcpdump_filter = ('icmp')
        tcpdump_helper = TcpdumpHelper(to_host, tcpdump_filter, [
                lambda: from_host.cmd('ping -c1 %s' % to_host.IP())])

        self.assertTrue(re.search('proto ICMP', tcpdump_helper.next_line()))
        next_line = tcpdump_helper.next_line()
        self.assertTrue(re.search('%s: ICMP echo request' % to_host.IP(), next_line), next_line)
        self.assertTrue(re.search('proto ICMP', tcpdump_helper.next_line()))
        next_line = tcpdump_helper.next_line()
        self.assertTrue(re.search('%s: ICMP echo reply' % from_host.IP(), next_line), next_line)
        self.assertFalse(re.search('ICMP', tcpdump_helper.next_line()))

        tcpdump_helper.wait()
