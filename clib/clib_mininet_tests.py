"""Mininet tests for clib."""


import os
import re

# Required to prevent circular import cycle.  pylint: disable=unused-import
from mininet.net import Mininet

from clib import mininet_test_base

from clib.tcpdump_helper import TcpdumpHelper
from clib.docker_host import make_docker_host


class FaucetSimpleTest(mininet_test_base.FaucetTestBase):
    """Basic untagged VLAN test."""

    N_UNTAGGED = 4
    N_TAGGED = 0
    LINKS_PER_HOST = 1
    CONFIG_GLOBAL = """
vlans:
    100:
        description: "untagged"
"""

    CONFIG = """
        interfaces:
            %(port_1)d:
                native_vlan: 100
                description: "b1"
            %(port_2)d:
                native_vlan: 100
                description: "b2"
            %(port_3)d:
                native_vlan: 100
                description: "b3"
            %(port_4)d:
                native_vlan: 100
                description: "b4"
"""

    def setUp(self):
        super(FaucetSimpleTest, self).setUp()
        self.topo = self.topo_class(
            self.OVS_TYPE, self.ports_sock, self._test_name(), [self.dpid],
            n_tagged=self.N_TAGGED, n_untagged=self.N_UNTAGGED,
            n_extended=self.N_EXTENDED, e_cls=self.EXTENDED_CLS,
            tmpdir=self.tmpdir, links_per_host=self.LINKS_PER_HOST,
            hw_dpid=self.hw_dpid)
        self.start_net()

    def test_ping_all(self):
        """All hosts should have connectivity."""
        self.ping_all_when_learned()


class FaucetTcpdumpHelperTest(FaucetSimpleTest):
    """Test for TcpdumpHelper class"""


    def _terminate_with_zero(self, tcpdump_helper):
        term_returns = tcpdump_helper.terminate()
        self.assertEqual(
            0, term_returns, msg='terminate code not 0: %d' % term_returns)

    def _terminate_with_nonzero(self, tcpdump_helper):
        term_returns = tcpdump_helper.terminate()
        self.assertNotEqual(
            0, term_returns, msg='terminate code s 0: %d' % term_returns)

    def test_tcpdump_execute(self):
        """Check tcpdump filter monitors ping using execute"""
        self.ping_all_when_learned()
        from_host = self.net.hosts[0]
        to_host = self.net.hosts[1]
        tcpdump_filter = ('icmp')
        tcpdump_helper = TcpdumpHelper(to_host, tcpdump_filter, [
            lambda: from_host.cmd('ping -c1 %s' % to_host.IP())])
        tcpdump_txt = tcpdump_helper.execute()
        self.assertTrue(re.search(
            '%s: ICMP echo request' % to_host.IP(), tcpdump_txt))
        self._terminate_with_zero(tcpdump_helper)

    def test_tcpdump_pcap(self):
        """Check tcpdump creates pcap output"""
        self.ping_all_when_learned()
        from_host = self.net.hosts[0]
        to_host = self.net.hosts[1]
        tcpdump_filter = ('icmp')
        pcap_file = os.path.join(self.tmpdir, 'out.pcap')
        tcpdump_helper = TcpdumpHelper(
            to_host, tcpdump_filter,
            [lambda: from_host.cmd('ping -c3 %s' % to_host.IP())],
            pcap_out=pcap_file, packets=None)
        tcpdump_helper.execute()
        self._terminate_with_zero(tcpdump_helper)
        result = from_host.cmd('tcpdump -en -r %s' % pcap_file)
        self.assertEqual(result.count('ICMP echo reply'), 3, 'three icmp echo replies')

    def test_tcpdump_noblock(self):
        """Check tcpdump uses nonblocking next_line"""
        self.ping_all_when_learned()
        from_host = self.net.hosts[0]
        to_host = self.net.hosts[1]
        tcpdump_filter = ('icmp')
        tcpdump_helper = TcpdumpHelper(
            to_host, tcpdump_filter,
            [lambda: from_host.cmd('ping -c10 %s' % to_host.IP())],
            blocking=False, packets=None)
        count = 0
        while tcpdump_helper.next_line():
            count = count + 1
            self.assertTrue(count < 10, 'Too many ping results before noblock')
        self._terminate_with_nonzero(tcpdump_helper)

    def test_tcpdump_nextline(self):
        """Check tcpdump filter monitors ping using next_line"""
        self.ping_all_when_learned()
        from_host = self.net.hosts[0]
        to_host = self.net.hosts[1]
        tcpdump_filter = ('icmp')
        tcpdump_helper = TcpdumpHelper(to_host, tcpdump_filter, [
            lambda: from_host.cmd('ping -c5 -i2 %s' % to_host.IP())])

        self.assertTrue(re.search('proto ICMP', tcpdump_helper.next_line()))
        next_line = tcpdump_helper.next_line()
        self.assertTrue(re.search('%s: ICMP echo request' % to_host.IP(), next_line), next_line)
        self.assertTrue(re.search('proto ICMP', tcpdump_helper.next_line()))
        next_line = tcpdump_helper.next_line()
        self.assertTrue(re.search('%s: ICMP echo reply' % from_host.IP(), next_line), next_line)
        self.assertFalse(re.search('ICMP', tcpdump_helper.next_line()))
        while tcpdump_helper.next_line():
            pass
        self._terminate_with_zero(tcpdump_helper)


class FaucetDockerHostTest(FaucetSimpleTest):
    """Test basic docker host functionality"""

    N_UNTAGGED = 2
    N_EXTENDED = 2
    EXTENDED_CLS = make_docker_host('faucet/test-host')

    def test_containers(self):
        """Test containers to make sure they're actually docker."""
        count = 0
        host_name = None

        for host in self.net.hosts:
            marker = host.cmd('cat /root/test_marker.txt').strip()
            if marker == 'faucet-test-host':
                host_name = host.name
                count = count + 1
                host.activate()
                host.wait()

        self.assertTrue(
            count == self.N_EXTENDED,
            'Found %d containers, expected %d' % (count, self.N_EXTENDED))

        self.assertTrue(
            os.path.exists(
                os.path.join(self.tmpdir, host_name, 'tmp')),
            'container tmp dir missing')

        host_log = os.path.join(self.tmpdir, host_name, 'activate.log')
        with open(host_log, 'r') as host_log_file:
            lines = host_log_file.readlines()
            output = ' '.join(lines).strip()
            self.assertEqual(output, 'hello faucet')
