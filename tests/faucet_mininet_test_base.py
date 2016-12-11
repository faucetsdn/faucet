#!/usr/bin/python

"""Base class for all FAUCET unit tests."""

import json
import os
import re
import shutil
import time
import unittest
import yaml

import ipaddr
import requests

from mininet.node import Host
from mininet.node import OVSSwitch


class FaucetSwitch(OVSSwitch):
    """Switch that will be used by all tests (kernel based OVS)."""

    def __init__(self, name, **params):
        OVSSwitch.__init__(
            self, name=name, datapath='kernel', **params)


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

    config = None
    dpid = None
    hardware = 'Open vSwitch'
    hw_switch = False
    net = None
    tmpdir = None

    def __init__(self, name, config):
        super(FaucetTestBase, self).__init__(name)
        self.config = config

    def tearDown(self):
        """Clean up after a test."""
        if self.net is not None:
            self.net.stop()
        shutil.rmtree(self.tmpdir)

    def get_config_header(self, config_global, debug_log, dpid, hardware):
        """Build v2 FAUCET config header."""
        return """
version: 2
%s
dps:
    faucet-1:
        ofchannel_log: %s
        dp_id: 0x%x
        hardware: "%s"
""" % (config_global, debug_log, int(dpid), hardware)

    def get_gauge_config(self, faucet_config_file,
                         monitor_stats_file,
                         monitor_state_file,
                         monitor_flow_table_file):
        """Build Gauge config."""
        return """
version: 2
faucet_configs:
    - %s
watchers:
    port_stats:
        dps: ['faucet-1']
        type: 'port_stats'
        interval: 5
        db: 'stats_file'
    port_state:
        dps: ['faucet-1']
        type: 'port_state'
        interval: 5
        db: 'state_file'
    flow_table:
        dps: ['faucet-1']
        type: 'flow_table'
        interval: 5
        db: 'flow_file'
dbs:
    stats_file:
        type: 'text'
        file: %s
    state_file:
        type: 'text'
        file: %s
    flow_file:
        type: 'text'
        file: %s
""" % (faucet_config_file, monitor_stats_file,
       monitor_state_file, monitor_flow_table_file)

    def get_controller(self):
        """Return the first (only) controller."""
        return self.net.controllers[0]

    def ofctl_rest_url(self):
        """Return control URL for Ryu ofctl module."""
        return 'http://127.0.0.1:%u' % self.get_controller().ofctl_port

    def get_all_flows_from_dpid(self, dpid, timeout=10):
        """Return all flows from DPID."""
        for _ in range(timeout):
            try:
                ofctl_result = json.loads(requests.get(
                    '%s/stats/flow/%s' % (self.ofctl_rest_url(), dpid)).text)
            except (ValueError, requests.exceptions.ConnectionError):
                # Didn't get valid JSON, try again
                time.sleep(1)
                continue
            flow_dump = ofctl_result[dpid]
            return [json.dumps(flow) for flow in flow_dump]
        return []

    def get_matching_flow_on_dpid(self, dpid, exp_flow, timeout=10):
        """Return flow matching an RE from DPID."""
        for _ in range(timeout):
            flow_dump = self.get_all_flows_from_dpid(dpid)
            for flow in flow_dump:
                if re.search(exp_flow, flow):
                    return json.loads(flow)
            time.sleep(1)
        return {}

    def get_matching_flow(self, exp_flow, timeout=10):
        """Return flow matching an RE from default DPID."""
        return self.get_matching_flow_on_dpid(self.dpid, exp_flow, timeout)

    def matching_flow_present_on_dpid(self, dpid, exp_flow, timeout=10):
        """Return True if matching flow is present on a DPID."""
        if self.get_matching_flow_on_dpid(dpid, exp_flow, timeout):
            return True
        return False

    def matching_flow_present(self, exp_flow, timeout=10):
        """Return True if matching flow is present on default DPID."""
        return self.matching_flow_present_on_dpid(self.dpid, exp_flow, timeout)

    def wait_until_matching_flow(self, exp_flow, timeout=10):
        """Wait (require) for flow to be present on default DPID."""
        self.assertTrue(self.matching_flow_present(exp_flow, timeout),
                        msg=exp_flow)

    def host_learned(self, host, timeout=10):
        """Return True if a host has been learned on default DPID."""
        return self.matching_flow_present(
            '"table_id": 2,.+"dl_src": "%s"' % host.MAC(), timeout)

    def host_ipv4(self, host):
        """Return first IPv4/netmask for host's default interface."""
        host_ip_cmd = (
            r'ip -o -f inet addr show %s|grep -m 1 -Eo "[0-9\\.]+\/[0-9]+"')
        return host.cmd(host_ip_cmd % host.defaultIntf()).strip()

    def host_ipv6(self, host):
        """Return first IPv6/netmask for host's default interface."""
        host_ip_cmd = (
            r'ip -o -f inet6 addr show %s|grep -m 1 -Eo "[0-9a-f\:]+\/[0-9]+"')
        return host.cmd(host_ip_cmd % host.defaultIntf()).strip()

    def require_host_learned(self, host, retries=3):
        """Require a host be learned on default DPID."""
        host_ip = self.host_ipv4(host)
        ping_cmd = 'ping'
        if not host_ip:
            host_ip = self.host_ipv6(host)
        broadcast = ipaddr.IPNetwork(host_ip)
        if broadcast.version == 6:
            ping_cmd = 'ping6'
        for _ in range(retries):
            if self.host_learned(host, timeout=1):
                return
            # stimulate host learning with a broadcast ping
            host.cmd('%s -i 0.2 -c 1 -b %s' % (ping_cmd, broadcast))
        self.fail('host %s could not be learned' % host)

    def wait_debug_log(self):
        """Require all switches to have exchanged flows with controller."""
        config = yaml.load(open(os.environ['FAUCET_CONFIG']))
        for dp_name, dp_config in config['dps'].iteritems():
            debug_log = dp_config['ofchannel_log']
            debug_log_present = False
            for _ in range(20):
                if (os.path.exists(debug_log) and
                        os.path.getsize(debug_log) > 0):
                    debug_log_present = True
                    break
                time.sleep(1)
            if not debug_log_present:
                self.fail(
                    'no controller debug log for switch %s' % dp_name)

    def hup_faucet(self):
        """Send a HUP signal to the controller."""
        controller = self.get_controller()
        tcp_pattern = '%s/tcp' % controller.port
        fuser_out = controller.cmd('fuser %s -k -1' % tcp_pattern)
        self.assertTrue(re.search(r'%s:\s+\d+' % tcp_pattern, fuser_out))

    def force_faucet_reload(self, new_config):
        """Force FAUCET to reload by adding new line to config file."""
        open(os.environ['FAUCET_CONFIG'], 'a').write(new_config)
        self.hup_faucet()

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
        self.assertEquals(
            '',
            host.cmd('ip -6 addr add %s dev %s' % (ip_v6, host.intf())))

    def add_host_ipv6_route(self, host, ip_dst, ip_gw):
        """Add an IPv6 route to a Mininet host."""
        host.cmd('ip -6 route add %s via %s' % (ip_dst.masked(), ip_gw))

    def add_host_ipv4_route(self, host, ip_dst, ip_gw):
        """Add an IPv4 route to a Mininet host."""
        host.cmd('ip -4 route add %s via %s' % (ip_dst.masked(), ip_gw))

    def one_ipv4_ping(self, host, dst, retries=3):
        """Ping an IPv4 destination from a host."""
        self.require_host_learned(host)
        for _ in range(retries):
            ping_result = host.cmd('ping -c1 %s' % dst)
            if re.search(self.ONE_GOOD_PING, ping_result):
                return
        self.assertTrue(re.search(self.ONE_GOOD_PING, ping_result))

    def one_ipv4_controller_ping(self, host):
        """Ping the controller from a host with IPv4."""
        self.one_ipv4_ping(host, self.CONTROLLER_IPV4)

    def one_ipv6_ping(self, host, dst, retries=3):
        """Ping an IPv6 destination from a host."""
        self.require_host_learned(host)
        # TODO: retry our one ping. We should not have to retry.
        for _ in range(retries):
            ping_result = host.cmd('ping6 -c1 %s' % dst)
            if re.search(self.ONE_GOOD_PING, ping_result):
                return
        self.assertTrue(re.search(self.ONE_GOOD_PING, ping_result))

    def one_ipv6_controller_ping(self, host):
        """Ping the controller from a host with IPv6."""
        self.one_ipv6_ping(host, self.CONTROLLER_IPV6)

    def wait_for_tcp_listen(self, host, port, timeout=10):
        """Wait for a host to start listening on a port."""
        for _ in range(timeout):
            fuser_out = host.cmd('fuser -n tcp %u' % port)
            if re.search(r'.*%u/tcp.*' % port, fuser_out):
                return
            time.sleep(1)
        self.fail('%s never listened on port %u (%s)' % (host, port, fuser_out))

    def serve_hello_on_tcp_port(self, host, port):
        """Serve 'hello' on a TCP port on a host."""
        host.cmd('timeout 10s echo hello | nc -l %s %u &' % (host.IP(), port))
        self.wait_for_tcp_listen(host, port)

    def verify_tp_dst_blocked(self, port, first_host, second_host):
        """Verify that a TCP port on a host is blocked from another host."""
        self.serve_hello_on_tcp_port(second_host, port)
        self.assertEquals(
            '', first_host.cmd('timeout 10s nc %s %u' % (second_host.IP(), port)))
        self.wait_until_matching_flow(
            r'"packet_count": [1-9]+.+"tp_dst": %u' % port)

    def verify_tp_dst_notblocked(self, port, first_host, second_host):
        """Verify that a TCP port on a host is NOT blocked from another host."""
        self.serve_hello_on_tcp_port(second_host, port)
        self.assertEquals(
            'hello\r\n',
            first_host.cmd('nc -w 5 %s %u' % (second_host.IP(), port)))
        self.wait_until_matching_flow(
            r'"packet_count": [1-9]+.+"tp_dst": %u' % port)

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
        self.wait_for_tcp_listen(controller, port)
        return exabgp_log

    def wait_bgp_up(self, exabgp_log):
        """Wait for BGP to come up."""
        for _ in range(60):
            exabgp_log_content = open(exabgp_log).read()
            if exabgp_log_content.find('OPENCONFIRM') > -1:
                return
            time.sleep(1)
        self.fail('exabgp did not peer with FAUCET')

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

    def wait_exabgp_sent_updates(self, exabgp_log):
        """Verify that exabgp process has sent BGP updates."""
        for _ in range(60):
            exabgp_log_content = open(exabgp_log).read()
            if re.search(r'>> [1-9]+[0-9]* UPDATE', exabgp_log_content):
                return
            time.sleep(1)
        self.fail('exabgp did not send BGP updates')

    def ping_all_when_learned(self, retries=3):
        """Verify all hosts can ping each other once FAUCET has learned all."""
        # Cause hosts to send traffic that FAUCET can use to learn them.
        for _ in range(retries):
            loss = self.net.pingAll()
            # we should have learned all hosts now, so should have no loss.
            for host in self.net.hosts:
                self.require_host_learned(host)
            if loss == 0:
                return
        self.assertEquals(0, loss)

    def wait_for_route_as_flow(self, nexthop, prefix, timeout=5):
        """Verify a route has been added as a flow."""
        if prefix.version == 6:
            exp_prefix = '/'.join(
                (str(prefix.masked().ip), str(prefix.netmask)))
            nw_dst_match = '"ipv6_dst": "%s"' % exp_prefix
        else:
            exp_prefix = prefix.masked().with_netmask
            nw_dst_match = '"nw_dst": "%s"' % exp_prefix
        self.wait_until_matching_flow(
            'SET_FIELD: {eth_dst:%s}.+%s' % (nexthop, nw_dst_match), timeout)

    def host_ipv4_alias(self, host, alias_ip):
        del_cmd = 'ip addr del %s/%s dev %s' % (
            alias_ip.ip, alias_ip.prefixlen, host.intf())
        add_cmd = 'ip addr add %s/%s dev %s label %s:1' % (
            alias_ip.ip, alias_ip.prefixlen, host.intf(), host.intf())
        host.cmd(del_cmd)
        self.assertEquals('', host.cmd(add_cmd))

    def verify_ipv4_routing(self, first_host, first_host_routed_ip,
                            second_host, second_host_routed_ip):
        """Verify one host can IPV4 route to another via FAUCET."""
        self.host_ipv4_alias(first_host, first_host_routed_ip)
        self.host_ipv4_alias(second_host, second_host_routed_ip)
        self.add_host_ipv4_route(
            first_host, second_host_routed_ip, self.CONTROLLER_IPV4)
        self.add_host_ipv4_route(
            second_host, first_host_routed_ip, self.CONTROLLER_IPV4)
        self.net.ping(hosts=(first_host, second_host))
        self.wait_for_route_as_flow(
            first_host.MAC(), first_host_routed_ip)
        self.wait_for_route_as_flow(
            second_host.MAC(), second_host_routed_ip)
        self.one_ipv4_ping(first_host, second_host_routed_ip.ip)
        self.one_ipv4_ping(second_host, first_host_routed_ip.ip)

    def verify_ipv4_routing_mesh(self):
        """Verify hosts can route to each other via FAUCET."""
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_routed_ip = ipaddr.IPv4Network('10.0.1.1/24')
        second_host_routed_ip = ipaddr.IPv4Network('10.0.2.1/24')
        second_host_routed_ip2 = ipaddr.IPv4Network('10.0.3.1/24')
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip2)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip2)

    def setup_ipv6_hosts_addresses(self, first_host, first_host_ip,
                                   first_host_routed_ip, second_host,
                                   second_host_ip, second_host_routed_ip):
        """Configure host IPv6 addresses for testing."""
        for host in first_host, second_host:
            host.cmd('ip addr flush dev %s' % host.intf())
        self.add_host_ipv6_address(first_host, first_host_ip)
        self.add_host_ipv6_address(second_host, second_host_ip)
        self.add_host_ipv6_address(first_host, first_host_routed_ip)
        self.add_host_ipv6_address(second_host, second_host_routed_ip)

    def verify_ipv6_routing(self, first_host, first_host_ip,
                            first_host_routed_ip, second_host,
                            second_host_ip, second_host_routed_ip):
        """Verify one host can IPV6 route to another via FAUCET."""
        self.one_ipv6_ping(first_host, second_host_ip.ip)
        self.one_ipv6_ping(second_host, first_host_ip.ip)
        self.add_host_ipv6_route(
            first_host, second_host_routed_ip, self.CONTROLLER_IPV6)
        self.add_host_ipv6_route(
            second_host, first_host_routed_ip, self.CONTROLLER_IPV6)
        self.wait_for_route_as_flow(
            first_host.MAC(), first_host_routed_ip)
        self.wait_for_route_as_flow(
            second_host.MAC(), second_host_routed_ip)
        self.one_ipv6_controller_ping(first_host)
        self.one_ipv6_controller_ping(second_host)
        self.one_ipv6_ping(first_host, second_host_routed_ip.ip)
        self.one_ipv6_ping(second_host, first_host_routed_ip.ip)

    def verify_ipv6_routing_pair(self, first_host, first_host_ip,
                                 first_host_routed_ip, second_host,
                                 second_host_ip, second_host_routed_ip):
        """Verify hosts can route IPv6 to each other via FAUCET."""
        self.setup_ipv6_hosts_addresses(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)

    def verify_ipv6_routing_mesh(self):
        """Verify IPv6 routing between hosts and multiple subnets."""
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_ip = ipaddr.IPv6Network('fc00::1:1/112')
        second_host_ip = ipaddr.IPv6Network('fc00::1:2/112')
        first_host_routed_ip = ipaddr.IPv6Network('fc00::10:1/112')
        second_host_routed_ip = ipaddr.IPv6Network('fc00::20:1/112')
        second_host_routed_ip2 = ipaddr.IPv6Network('fc00::30:1/112')
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2)
