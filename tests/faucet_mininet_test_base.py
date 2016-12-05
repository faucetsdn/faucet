#!/usr/bin/python

"""Base class for all FAUCET unit tests."""

import os
import re
import shutil
import time
import unittest

from mininet.node import Host
from mininet.node import OVSSwitch

import faucet_mininet_test_util


class FaucetSwitch(OVSSwitch):
    """Switch that will be used by all tests (kernel based OVS)."""

    def __init__(self, name, **params):
        OVSSwitch.__init__(self, name=name, datapath='kernel', **params)


class VLANHost(Host):
    """Implementation of a Mininet host on a tagged VLAN."""

    def config(self, vlan=100, **params):
        """Configure VLANHost according to (optional) parameters:
           vlan: VLAN ID for default interface"""
        super_config = super(VLANHost, self).config(**params)
        intf = self.defaultIntf()
        self.cmd('ifconfig %s inet 0' % intf)
        self.cmd('vconfig add %s %d' % (intf, vlan))
        self.cmd('ifconfig %s.%d inet %s' % (intf, vlan, params['ip']))
        vlan_intf_name = '%s.%d' % (intf, vlan)
        intf.name = vlan_intf_name
        self.nameToIntf[vlan_intf_name] = intf
        return super_config


class FaucetTestBase(unittest.TestCase):
    """Base class for all FAUCET unit tests."""

    ONE_GOOD_PING = '1 packets transmitted, 1 received, 0% packet loss'
    CONFIG = ''
    CONTROLLER_IPV4 = '10.0.0.254'
    CONTROLLER_IPV6 = 'fc00::1:254'
    OFCTL = 'ovs-ofctl -OOpenFlow13'
    CONFIG_GLOBAL = ''
    BOGUS_MAC = '01:02:03:04:05:06'

    net = None
    tmpdir = None

    def tearDown(self):
        if self.net is not None:
            self.net.stop()
        shutil.rmtree(self.tmpdir)

    def get_config_header(self, config_global, dpid, hardware):
        """Build v2 FAUCET config header."""
        return """
version: 2
%s
dps:
    faucet-1:
        dp_id: %s
        hardware: "%s"
""" % (config_global, faucet_mininet_test_util.str_int_dpid(dpid), hardware)

    def get_gauge_config(self, faucet_config_file, monitor_ports_file,
                         monitor_flow_table_file):
        """Build Gauge config."""
        return """
faucet_configs:
    - %s
watchers:
    port_stats:
        dps: ['faucet-1']
        type: 'port_stats'
        interval: 5
        db: 'ps_file'
    flow_table:
        dps: ['faucet-1']
        type: 'flow_table'
        interval: 5
        db: 'ft_file'
dbs:
    ps_file:
        type: 'text'
        file: %s
    ft_file:
        type: 'text'
        file: %s
""" % (faucet_config_file, monitor_ports_file, monitor_flow_table_file)

    def get_controller(self):
        """Return the first (only) controller."""
        return self.net.controllers[0]

    def ofctl_rest_url(self):
        """Return control URL for Ryu ofctl module."""
        return 'http://127.0.0.1:%u' % self.get_controller().ofctl_port

    def hup_faucet(self):
        """Send a HUP signal to the controller."""
        controller = self.get_controller()
        tcp_pattern = '%s/tcp' % controller.port
        fuser_out = controller.cmd('fuser %s -k -1' % tcp_pattern)
        self.assertTrue(re.search(r'%s:\s+\d+' % tcp_pattern, fuser_out))

    def curl_portmod(self, int_dpid, port_no, config, mask):
        """Use curl to send a portmod command via the ofctl module."""
        curl_format = ' '.join((
            'curl -X POST -d'
            '\'{"dpid": %s, "port_no": %u, "config": %u, "mask": %u}\'',
            '%s/stats/portdesc/modify'))
        return curl_format  % (
            int_dpid, port_no, config, mask, self.ofctl_rest_url())

    def add_host_ipv6_address(self, host, ip_v6):
        """Add an IPv6 address to a Mininet host."""
        host.cmd('ip -6 addr add %s dev %s' % (ip_v6, host.intf()))

    def add_host_ipv6_route(self, host, ip_dst, ip_gw):
        """Add an IPv6 route to a Mininet host."""
        host.cmd('ip -6 route add %s via %s' % (ip_dst.masked(), ip_gw))

    def add_host_ipv4_route(self, host, ip_dst, ip_gw):
        """Add an IPv4 route to a Mininet host."""
        host.cmd('ip -4 route add %s via %s' % (ip_dst.masked(), ip_gw))

    def swap_host_macs(self, first_host, second_host):
        """Swap the MAC addresses of two Mininet hosts."""
        first_host_mac = first_host.MAC()
        second_host_mac = second_host.MAC()
        first_host.setMAC(second_host_mac)
        second_host.setMAC(first_host_mac)

    def start_exabgp(self, exabgp_conf, listen_address='127.0.0.1', port=179):
        """Start exabgp process on controller host."""
        self.stop_exabgp(port)
        exabgp_conf_file = os.path.join(self.tmpdir, 'exabgp.conf')
        exabgp_log = os.path.join(self.tmpdir, 'exabgp.log')
        exabgp_err = os.path.join(self.tmpdir, 'exabgp.err')
        open(exabgp_conf_file, 'w').write(exabgp_conf)
        controller = self.get_controller()
        controller.cmd(
            'env exabgp.tcp.bind="%s" exabgp.tcp.port=%u '
            'timeout -s9 180s stdbuf -o0 -e0 exabgp %s -d 2> %s > %s &' % (
                listen_address, port, exabgp_conf_file, exabgp_err, exabgp_log))
        for _ in range(60):
            netstat = controller.cmd('netstat -an|grep %s:%s|grep ESTAB' % (
                listen_address, port))
            if netstat.find('ESTAB') > -1:
                return exabgp_log
            time.sleep(1)
        self.fail('exabgp did not start')

    def stop_exabgp(self, port=179):
        """Stop exabgp process on controller host."""
        controller = self.get_controller()
        controller.cmd('fuser %s/tcp -k -9' % port)

    def exabgp_updates(self, exabgp_log):
        """Verify that exabgp process has received BGP updates."""
        controller = self.get_controller()
        # exabgp should have received our BGP updates
        for _ in range(60):
            updates = controller.cmd(
                r'grep UPDATE %s |grep -Eo "\S+ next-hop \S+"' % exabgp_log)
            if updates:
                return updates
            time.sleep(1)
        self.fail('exabgp did not receive BGP updates')
