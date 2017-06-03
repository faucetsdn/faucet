#!/usr/bin/env python

"""Base class for all FAUCET unit tests."""

import json
import os
import random
import re
import shutil
import socket
import string
import subprocess
import tempfile
import time
import unittest
import yaml

import ipaddress
import netifaces
import requests

from mininet.net import Mininet
from mininet.node import Controller
from mininet.node import Host
from mininet.node import Intf
from mininet.node import OVSSwitch
from mininet.topo import Topo
from mininet.util import dumpNodeConnections, pmonitor
from ryu.ofproto import ofproto_v1_3 as ofp

import faucet_mininet_test_util


class BaseFAUCET(Controller):

    controller_intf = None
    tmpdir = None

    def _start_tcpdump(self):
        tcpdump_args = ' '.join((
            '-s 0',
            '-e',
            '-n',
            '-U',
            '-q',
            '-i %s' % self.controller_intf,
            '-w %s/%s-of.cap' % (self.tmpdir, self.name),
            'tcp and port %u' % self.port,
            '>/dev/null',
            '2>/dev/null',
        ))
        self.cmd('tcpdump %s &' % tcpdump_args)

    def _tls_cargs(self, ofctl_port, ctl_privkey, ctl_cert, ca_certs):
        tls_cargs = []
        for carg_val, carg_key in ((ctl_privkey, 'ctl-privkey'),
                                   (ctl_cert, 'ctl-cert'),
                                   (ca_certs, 'ca-certs')):
            if carg_val:
                tls_cargs.append(('--%s=%s' % (carg_key, carg_val)))
        if tls_cargs:
            tls_cargs.append(('--ofp-ssl-listen-port=%u' % ofctl_port))
        return ' '.join(tls_cargs)

    def start(self):
        self._start_tcpdump()
        super(BaseFAUCET, self).start()


class FAUCET(BaseFAUCET):
    """Start a FAUCET controller."""

    def __init__(self, name, tmpdir, controller_intf,
                 ctl_privkey, ctl_cert, ca_certs,
                 ports_sock, port, **kwargs):
        name = 'faucet-%u' % os.getpid()
        self.tmpdir = tmpdir
        self.controller_intf = controller_intf
        # pylint: disable=no-member
        self.controller_ipv4 = netifaces.ifaddresses(
            self.controller_intf)[socket.AF_INET][0]['addr']
        self.ofctl_port, _ = faucet_mininet_test_util.find_free_port(
            ports_sock)
        command = 'PYTHONPATH=../ ryu-manager ryu.app.ofctl_rest faucet.faucet'
        cargs = ' '.join((
            '--verbose',
            '--use-stderr',
            '--wsapi-host=127.0.0.1',
            '--wsapi-port=%u' % self.ofctl_port,
            '--ofp-listen-host=%s' % self.controller_ipv4,
            '--ofp-tcp-listen-port=%s',
            self._tls_cargs(port, ctl_privkey, ctl_cert, ca_certs)))
        Controller.__init__(
            self,
            name,
            cdir=faucet_mininet_test_util.FAUCET_DIR,
            command=command,
            cargs=cargs,
            port=port,
            **kwargs)


class Gauge(BaseFAUCET):
    """Start a Gauge controller."""

    def __init__(self, name, tmpdir, controller_intf,
                 ctl_privkey, ctl_cert, ca_certs,
                 port, **kwargs):
        name = 'gauge-%u' % os.getpid()
        self.tmpdir = tmpdir
        self.controller_intf = controller_intf
        command = 'PYTHONPATH=../ ryu-manager faucet.gauge'
        cargs = ' '.join((
            '--verbose',
            '--use-stderr',
            '--ofp-tcp-listen-port=%s',
            self._tls_cargs(port, ctl_privkey, ctl_cert, ca_certs)))
        Controller.__init__(
            self,
            name,
            cdir=faucet_mininet_test_util.FAUCET_DIR,
            command=command,
            cargs=cargs,
            port=port,
            **kwargs)


class FaucetAPI(Controller):
    '''Start a controller to run the Faucet API tests.'''

    def __init__(self, name, **kwargs):
        name = 'faucet-api-%u' % os.getpid()
        command = 'PYTHONPATH=../ ryu-manager faucet.faucet test_api.py'
        cargs = ' '.join((
            '--verbose',
            '--use-stderr',
            '--ofp-tcp-listen-port=%s'))
        Controller.__init__(
            self,
            name,
            command=command,
            cargs=cargs,
            **kwargs)


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
        vlan_intf_name = '%s.%d' % (intf, vlan)
        self.cmd('ip -4 addr flush dev %s' % intf)
        self.cmd('ip -6 addr flush dev %s' % intf)
        self.cmd('vconfig add %s %d' % (intf, vlan))
        self.cmd('ip link set dev %s up' % vlan_intf_name)
        self.cmd('ip -4 addr add %s dev %s' % (params['ip'], vlan_intf_name))
        intf.name = vlan_intf_name
        self.nameToIntf[vlan_intf_name] = intf
        return super_config


class FaucetSwitchTopo(Topo):
    """FAUCET switch topology that contains a software switch."""

    def _get_sid_prefix(self, ports_served):
        """Return a unique switch/host prefix for a test."""
        # Linux tools require short interface names.
        id_chars = string.letters + string.digits
        id_a = int(ports_served / len(id_chars))
        id_b = ports_served - (id_a * len(id_chars))
        return '%s%s' % (
            id_chars[id_a], id_chars[id_b])

    def _add_tagged_host(self, sid_prefix, tagged_vid, host_n):
        """Add a single tagged test host."""
        host_name = 't%s%1.1u' % (sid_prefix, host_n + 1)
        return self.addHost(
            name=host_name,
            cls=VLANHost,
            vlan=tagged_vid)

    def _add_untagged_host(self, sid_prefix, host_n):
        """Add a single untagged test host."""
        host_name = 'u%s%1.1u' % (sid_prefix, host_n + 1)
        return self.addHost(name=host_name)

    def _add_faucet_switch(self, sid_prefix, port, dpid):
        """Add a FAUCET switch."""
        switch_name = 's%s' % sid_prefix
        return self.addSwitch(
            name=switch_name,
            cls=FaucetSwitch,
            listenPort=port,
            dpid=faucet_mininet_test_util.mininet_dpid(dpid))

    def build(self, ports_sock, dpid=0, n_tagged=0, tagged_vid=100, n_untagged=0):
        port, ports_served = faucet_mininet_test_util.find_free_port(ports_sock)
        sid_prefix = self._get_sid_prefix(ports_served)
        for host_n in range(n_tagged):
            self._add_tagged_host(sid_prefix, tagged_vid, host_n)
        for host_n in range(n_untagged):
            self._add_untagged_host(sid_prefix, host_n)
        switch = self._add_faucet_switch(sid_prefix, port, dpid)
        for host in self.hosts():
            self.addLink(host, switch)


class FaucetHwSwitchTopo(FaucetSwitchTopo):
    """FAUCET switch topology that contains a hardware switch."""

    def build(self, ports_sock, dpid=0, n_tagged=0, tagged_vid=100, n_untagged=0):
        port, ports_served = faucet_mininet_test_util.find_free_port(ports_sock)
        sid_prefix = self._get_sid_prefix(ports_served)
        for host_n in range(n_tagged):
            self._add_tagged_host(sid_prefix, tagged_vid, host_n)
        for host_n in range(n_untagged):
            self._add_untagged_host(sid_prefix, host_n)
        remap_dpid = str(int(dpid) + 1)
        print('bridging hardware switch DPID %s (%x) dataplane via OVS DPID %s (%x)' % (
            dpid, int(dpid), remap_dpid, int(remap_dpid)))
        dpid = remap_dpid
        switch = self._add_faucet_switch(sid_prefix, port, dpid)
        for host in self.hosts():
            self.addLink(host, switch)


class FaucetTestBase(unittest.TestCase):
    """Base class for all FAUCET unit tests."""

    ONE_GOOD_PING = '1 packets transmitted, 1 received, 0% packet loss'
    FAUCET_VIPV4 = ipaddress.ip_interface(u'10.0.0.254/24')
    FAUCET_VIPV4_2 = ipaddress.ip_interface(u'172.16.0.254/24')
    FAUCET_VIPV6 = ipaddress.ip_interface(u'fc00::1:254/64')
    FAUCET_VIPV6_2 = ipaddress.ip_interface(u'fc01::1:254/64')
    OFCTL = 'ovs-ofctl -OOpenFlow13'
    BOGUS_MAC = '01:02:03:04:05:06'
    FAUCET_MAC = '0e:00:00:00:00:01'
    LADVD = 'ladvd -e lo -f'
    ONEMBPS = (1024 * 1024)

    CONFIG = ''
    CONFIG_GLOBAL = ''

    N_UNTAGGED = 0
    N_TAGGED = 0

    RUN_GAUGE = True

    config = None
    dpid = None
    hardware = 'Open vSwitch'
    hw_switch = False
    gauge_of_port = None
    net = None
    of_port = None
    ctl_privkey = None
    ctl_cert = None
    ca_certs = None
    port_map = {'port_1': 1, 'port_2': 2, 'port_3': 3, 'port_4': 4}
    switch_map = {}
    tmpdir = None
    net = None
    topo = None
    cpn_intf = None

    def __init__(self, name, config, root_tmpdir, ports_sock):
        super(FaucetTestBase, self).__init__(name)
        self.config = config
        self.root_tmpdir = root_tmpdir
        self.ports_sock = ports_sock

    def tmpdir_name(self):
        test_name = '-'.join(self.id().split('.')[1:])
        return tempfile.mkdtemp(
            prefix='%s-' % test_name, dir=self.root_tmpdir)

    def timeout_cmd(self, cmd, timeout):
        return 'timeout -sKILL %us stdbuf -o0 -e0 %s' % (timeout, cmd)

    def timeout_soft_cmd(self, cmd, timeout):
        return 'timeout %us stdbuf -o0 -e0 %s' % (timeout, cmd)

    def verify_no_exception(self, exception_log):
        exception_log_name = os.environ[exception_log]
        if not os.path.exists(exception_log_name):
            return
        exception_contents = open(exception_log_name, 'r').read()
        self.assertEquals(
            '',
            exception_contents,
            msg='%s log contains %s' % (exception_log, exception_contents))

    def attach_physical_switch(self):
        """Bridge a physical switch into test topology."""
        switch = self.net.switches[0]
        mapped_base = max(len(self.switch_map), len(self.port_map))
        for i, test_host_port in enumerate(sorted(self.switch_map)):
            port_i = i + 1
            mapped_port_i = mapped_base + port_i
            phys_port = Intf(self.switch_map[test_host_port], node=switch)
            switch.cmd('ip link set dev %s up' % phys_port)
            switch.cmd(
                ('ovs-vsctl add-port %s %s -- '
                 'set Interface %s ofport_request=%u') % (
                     switch.name,
                     phys_port.name,
                     phys_port.name,
                     mapped_port_i))
            for port_pair in ((port_i, mapped_port_i), (mapped_port_i, port_i)):
                port_x, port_y = port_pair
                switch.cmd('%s add-flow %s in_port=%u,actions=output:%u' % (
                    self.OFCTL, switch.name, port_x, port_y))

    def start_net(self):
        """Start Mininet network."""
        controller_intf = 'lo'
        if self.hw_switch:
            controller_intf = self.cpn_intf
        self.net = Mininet(
            self.topo,
            controller=FAUCET(
                name='faucet', tmpdir=self.tmpdir,
                controller_intf=controller_intf,
                ctl_privkey=self.ctl_privkey,
                ctl_cert=self.ctl_cert,
                ca_certs=self.ca_certs,
                ports_sock=self.ports_sock,
                port=self.of_port))
        self.pre_start_net()
        if self.RUN_GAUGE:
            gauge_controller = Gauge(
                name='gauge', tmpdir=self.tmpdir,
                controller_intf=controller_intf,
                ctl_privkey=self.ctl_privkey,
                ctl_cert=self.ctl_cert,
                ca_certs=self.ca_certs,
                port=self.gauge_of_port)
            self.net.addController(gauge_controller)
        self.net.start()
        if self.hw_switch:
            self.attach_physical_switch()
        self.wait_debug_log()
        self.wait_dp_status(1)
        self.wait_until_matching_flow('OUTPUT:CONTROLLER')
        for port_no in self.port_map.values():
            self.set_port_up(port_no)
        dumpNodeConnections(self.net.hosts)

    def setUp(self):
        self.tmpdir = self.tmpdir_name()
        os.environ['FAUCET_CONFIG'] = os.path.join(
            self.tmpdir, 'faucet.yaml')
        os.environ['GAUGE_CONFIG'] = os.path.join(
            self.tmpdir, 'gauge.yaml')
        os.environ['FAUCET_LOG'] = os.path.join(
            self.tmpdir, 'faucet.log')
        os.environ['FAUCET_EXCEPTION_LOG'] = os.path.join(
            self.tmpdir, 'faucet-exception.log')
        os.environ['GAUGE_LOG'] = os.path.join(
            self.tmpdir, 'gauge.log')
        os.environ['GAUGE_EXCEPTION_LOG'] = os.path.join(
            self.tmpdir, 'gauge-exception.log')
        prom_port, _ = faucet_mininet_test_util.find_free_port(
            self.ports_sock)
        os.environ['FAUCET_PROMETHEUS_PORT'] = str(prom_port)
        self.debug_log_path = os.path.join(
            self.tmpdir, 'ofchannel.log')
        self.monitor_stats_file = os.path.join(
            self.tmpdir, 'ports.txt')
        self.monitor_state_file = os.path.join(
            self.tmpdir, 'state.txt')
        self.monitor_flow_table_file = os.path.join(
            self.tmpdir, 'flow.txt')
        if self.config is not None:
            if 'hw_switch' in self.config:
                self.hw_switch = self.config['hw_switch']
            if self.hw_switch:
                self.dpid = self.config['dpid']
                self.cpn_intf = self.config['cpn_intf']
                self.of_port = self.config['of_port']
                self.gauge_of_port = self.config['gauge_of_port']
                self.hardware = self.config['hardware']
                if 'ctl_privkey' in self.config:
                    self.ctl_privkey = self.config['ctl_privkey']
                if 'ctl_cert' in self.config:
                    self.ctl_cert = self.config['ctl_cert']
                if 'ca_certs' in self.config:
                    self.ca_certs = self.config['ca_certs']
                dp_ports = self.config['dp_ports']
                self.port_map = {}
                self.switch_map = {}
                for i, switch_port in enumerate(dp_ports):
                    test_port_name = 'port_%u' % (i + 1)
                    self.port_map[test_port_name] = switch_port
                    self.switch_map[test_port_name] = dp_ports[switch_port]

        if self.hw_switch:
            self.topo_class = FaucetHwSwitchTopo
            self.dpid = faucet_mininet_test_util.str_int_dpid(self.dpid)
        else:
            self.topo_class = FaucetSwitchTopo
            self.dpid = str(random.randint(1, 2**32))
            self.of_port, _ = faucet_mininet_test_util.find_free_port(
                self.ports_sock)
            self.gauge_of_port, _ = faucet_mininet_test_util.find_free_port(
                self.ports_sock)

        self.CONFIG = '\n'.join((
            self.get_config_header(
                self.CONFIG_GLOBAL, self.debug_log_path, self.dpid, self.hardware),
            self.CONFIG % self.port_map))
        open(os.environ['FAUCET_CONFIG'], 'w').write(self.CONFIG)
        self.influx_port, _ = faucet_mininet_test_util.find_free_port(
            self.ports_sock)
        self.GAUGE_CONFIG = self.get_gauge_config(
            os.environ['FAUCET_CONFIG'],
            self.monitor_stats_file,
            self.monitor_state_file,
            self.monitor_flow_table_file,
            self.influx_port,
            )
        open(os.environ['GAUGE_CONFIG'], 'w').write(self.GAUGE_CONFIG)

    def tearDown(self):
        """Clean up after a test."""
        controller_names = []
        for controller in self.net.controllers:
            controller_names.append(controller.name)
        open(os.path.join(self.tmpdir, 'prometheus.log'), 'w').write(
            self.scrape_prometheus())
        if self.net is not None:
            self.net.stop()
        # Associate controller log with test results, if we are keeping
        # the temporary directory, or effectively delete it if not.
        # mininet doesn't have a way to change its log name for the controller.
        for controller_name in controller_names:
            shutil.move('/tmp/%s.log' % controller_name, self.tmpdir)
        # must not be any controller exception.
        self.verify_no_exception('FAUCET_EXCEPTION_LOG')
        for _, debug_log in self.get_ofchannel_logs():
            self.assertFalse(
                re.search('OFPErrorMsg', open(debug_log).read()),
                msg='debug log has OFPErrorMsgs')

    def tcpdump_helper(self, tcpdump_host, tcpdump_filter, funcs=[],
                       vs='-v', timeout=10, packets=2, root_intf=False):
        intf = tcpdump_host.intf().name
        if root_intf:
            intf = intf.split('.')[0]
        tcpdump_cmd = self.timeout_soft_cmd(
            'tcpdump -i %s -e -n -U %s -c %u %s' % (
                intf, vs, packets, tcpdump_filter),
            timeout)
        tcpdump_out = tcpdump_host.popen(tcpdump_cmd, stderr=subprocess.STDOUT)
        popens = {tcpdump_host: tcpdump_out}
        tcpdump_started = False
        tcpdump_txt = ''
        for host, line in pmonitor(popens):
            if host == tcpdump_host:
                if tcpdump_started:
                    tcpdump_txt += line.strip()
                elif re.search('tcpdump: listening on ', line):
                    # when we see tcpdump start, then call provided functions.
                    tcpdump_started = True
                    for func in funcs:
                        func()
                else:
                    print('tcpdump_helper: %s' % line)
        self.assertTrue(tcpdump_started)
        return tcpdump_txt

    def pre_start_net(self):
        """Hook called after Mininet initializtion, before Mininet started."""
        return

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


    def get_gauge_watcher_config(self):
        return """
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
"""

    def get_gauge_config(self, faucet_config_file,
                         monitor_stats_file,
                         monitor_state_file,
                         monitor_flow_table_file,
                         influx_port):
        """Build Gauge config."""
        return """
version: 2
faucet_configs:
    - %s
watchers:
    %s
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
    influx:
        type: 'influx'
        influx_db: 'faucet'
        influx_host: 'localhost'
        influx_port: %u
        influx_user: 'faucet'
        influx_pwd: ''
        influx_timeout: 10
""" % (faucet_config_file,
       self.get_gauge_watcher_config(),
       monitor_stats_file,
       monitor_state_file,
       monitor_flow_table_file,
       influx_port)

    def get_controller(self):
        """Return the first (only) controller."""
        return self.net.controllers[0]

    def ofctl_rest_url(self):
        """Return control URL for Ryu ofctl module."""
        return 'http://127.0.0.1:%u' % self.get_controller().ofctl_port

    def ofctl_get(self, int_dpid, req, timeout):
        for _ in range(timeout):
            try:
                ofctl_result = json.loads(requests.get(req).text)
                ofmsgs = ofctl_result[int_dpid]
                return [json.dumps(ofmsg) for ofmsg in ofmsgs]
            except (ValueError, requests.exceptions.ConnectionError):
                # Didn't get valid JSON, try again
                time.sleep(1)
                continue
        return []

    def get_all_groups_desc_from_dpid(self, dpid, timeout=2):
        int_dpid = faucet_mininet_test_util.str_int_dpid(dpid)
        return self.ofctl_get(
            int_dpid,
            '%s/stats/groupdesc/%s' % (self.ofctl_rest_url(), int_dpid),
            timeout)

    def get_all_flows_from_dpid(self, dpid, timeout=10):
        """Return all flows from DPID."""
        int_dpid = faucet_mininet_test_util.str_int_dpid(dpid)
        return self.ofctl_get(
            int_dpid,
            '%s/stats/flow/%s' % (self.ofctl_rest_url(), int_dpid),
            timeout)

    def get_port_stats_from_dpid(self, dpid, port, timeout=2):
        """Return OFStats for a port."""
        int_dpid = faucet_mininet_test_util.str_int_dpid(dpid)
        port_stats = self.ofctl_get(
            int_dpid,
            '%s/stats/port/%s/%s' % (self.ofctl_rest_url(), int_dpid, port),
            timeout)
        if port_stats:
            return json.loads(port_stats[0])
        return None

    def get_group_id_for_matching_flow(self, exp_flow, timeout=10):
        for _ in range(timeout):
            flow_dump = self.get_all_flows_from_dpid(self.dpid, timeout)
            for flow in flow_dump:
                if re.search(exp_flow, flow):
                    flow = json.loads(flow)
                    group_id = int(re.findall(r'\d+', str(flow['actions']))[0])
                    return group_id
            time.sleep(1)
        self.fail(
            'Cannot find group_id for matching flow %s' % exp_flow)

    def wait_matching_in_group_table(self, exp_flow, group_id, timeout=10):
        exp_group = '%s.+"group_id": %d' % (exp_flow, group_id)
        for _ in range(timeout):
            group_dump = self.get_all_groups_desc_from_dpid(self.dpid, 1)
            for group_desc in group_dump:
                if re.search(exp_group, group_desc):
                    return True
            time.sleep(1)
        return False

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

    def mac_learned(self, mac, timeout=10):
        """Return True if a MAC has been learned on default DPID."""
        return self.matching_flow_present(
            '"table_id": 3,.+"dl_src": "%s"' % mac, timeout)

    def host_learned(self, host, timeout=10):
        """Return True if a host has been learned on default DPID."""
        return self.mac_learned(host.MAC(), timeout)

    def host_ip(self, host, family, family_re):
        host_ip_cmd = (
            r'ip -o -f %s addr show %s|'
            'grep -m 1 -Eo "%s %s"|cut -f2 -d " "' % (
                family,
                host.defaultIntf(),
                family,
                family_re))
        return host.cmd(host_ip_cmd).strip()

    def host_ipv4(self, host):
        """Return first IPv4/netmask for host's default interface."""
        return self.host_ip(host, 'inet', r'[0-9\\.]+\/[0-9]+')

    def host_ipv6(self, host):
        """Return first IPv6/netmask for host's default interface."""
        return self.host_ip(host, 'inet6', r'[0-9a-f\:]+\/[0-9]+')

    def require_host_learned(self, host, retries=3):
        """Require a host be learned on default DPID."""
        host_ip_net = self.host_ipv4(host)
        ping_cmd = 'ping'
        if not host_ip_net:
            host_ip_net = self.host_ipv6(host)
        broadcast = (ipaddress.ip_interface(unicode(host_ip_net)).network.broadcast_address)
        if broadcast.version == 6:
            ping_cmd = 'ping6'
        for _ in range(retries):
            if self.host_learned(host, timeout=1):
                return
            # stimulate host learning with a broadcast ping
            host.cmd('%s -i 0.2 -c 1 -b %s' % (ping_cmd, broadcast))
        self.fail('host %s could not be learned' % host)

    def get_ofchannel_logs(self):
        config = yaml.load(open(os.environ['FAUCET_CONFIG']))
        ofchannel_logs = []
        for dp_name, dp_config in config['dps'].items():
            if 'ofchannel_log' in dp_config:
                debug_log = dp_config['ofchannel_log']
                ofchannel_logs.append((dp_name, debug_log))
        return ofchannel_logs

    def wait_debug_log(self):
        """Require all switches to have exchanged flows with controller."""
        ofchannel_logs = self.get_ofchannel_logs()
        for dp_name, debug_log in ofchannel_logs:
            debug_log_present = False
            for _ in range(60):
                if (os.path.exists(debug_log) and
                        os.path.getsize(debug_log) > 0):
                    debug_log_present = True
                    break
                time.sleep(1)
            if not debug_log_present:
                # Maybe controller crashed.
                self.verify_no_exception('FAUCET_EXCEPTION_LOG')
                self.fail(
                    'no controller debug log for switch %s' % dp_name)

    def scrape_prometheus(self):
        prom_port = int(os.getenv('FAUCET_PROMETHEUS_PORT'))
        prom_url = 'http://127.0.0.1:%u' % prom_port
        prom_vars = []
        for prom_line in requests.get(prom_url).text.split('\n'):
            if not prom_line.startswith('#'):
                prom_vars.append(prom_line)
        return '\n'.join(prom_vars)

    def scrape_prometheus_var(self, var, labels=None, default=None, dpid=True, multiple=False):
        label_values_re = ''
        if labels is None:
            labels = {}
        if dpid:
            labels.update({'dpid': '0x%x' % long(self.dpid)})
        if labels:
            label_values = []
            for label, value in sorted(list(labels.items())):
                label_values.append('%s="%s"' % (label, value))
            label_values_re = r'\{%s\}' % r'\S+'.join(label_values)
        results = []
        var_re = r'^%s%s$' % (var, label_values_re)
        for prom_line in self.scrape_prometheus().splitlines():
            var, value = prom_line.split(' ')
            var_match = re.search(var_re, var)
            if var_match:
                value_int = long(float(value))
                results.append((var, value_int))
                if not multiple:
                    break
        if results:
            if multiple:
                return results
            else:
                return results[0][1]
        return default

    def gauge_smoke_test(self):
        watcher_files = (
            self.monitor_stats_file,
            self.monitor_state_file,
            self.monitor_flow_table_file)
        for watcher_file in watcher_files:
            for _ in range(60):
                if os.path.exists(watcher_file):
                    break
                time.sleep(1)
            if (os.path.exists(watcher_file) and
                    os.stat(watcher_file).st_size > 0):
                continue
            self.fail(
                'gauge did not output %s (gauge not connected?)' % watcher_file)
        self.verify_no_exception('FAUCET_EXCEPTION_LOG')
        self.verify_no_exception('GAUGE_EXCEPTION_LOG')

    def prometheus_smoke_test(self):
        prom_out = self.scrape_prometheus()
        self.assertTrue(re.search(r'of_packet_ins\S+[1-9]+', prom_out), msg=prom_out)
        self.assertTrue(re.search(r'of_flowmsgs_sent\S+[1-9]+', prom_out), msg=prom_out)
        self.assertTrue(re.search(r'of_dp_connections\S+[1-9]+', prom_out), msg=prom_out)
        self.assertTrue(re.search(r'faucet_config\S+name=\"flood\"\S+', prom_out), msg=prom_out)
        self.assertIsNone(re.search(r'of_errors', prom_out), msg=prom_out)
        self.assertIsNone(re.search(r'of_dp_disconnections', prom_out), msg=prom_out)

    def get_configure_count(self):
        """Return the number of times FAUCET has processed a reload request."""
        for _ in range(3):
            count = self.scrape_prometheus_var(
                'faucet_config_reload_requests', default=None, dpid=False)
            if count is not None:
                return count
            time.sleep(1)
        self.fail('configure count stayed zero')

    def signal_proc_on_port(self, host, port, signal):
        tcp_pattern = '%s/tcp' % port
        fuser_out = host.cmd('fuser %s -k -%u' % (tcp_pattern, signal))
        return re.search(r'%s:\s+\d+' % tcp_pattern, fuser_out)

    def hup_faucet(self):
        """Send a HUP signal to the controller."""
        controller = self.get_controller()
        self.assertTrue(self.signal_proc_on_port(controller, controller.port, 1))

    def verify_ping_mirrored(self, first_host, second_host, mirror_host):
        self.net.ping((first_host, second_host))
        for host in (first_host, second_host):
            self.require_host_learned(host)
        self.assertEquals(0, self.net.ping((first_host, second_host)))
        mirror_mac = mirror_host.MAC()
        tcpdump_filter = (
            'not ether src %s and '
            '(icmp[icmptype] == 8 or icmp[icmptype] == 0)') % mirror_mac
        first_ping_second = 'ping -c1 %s' % second_host.IP()
        tcpdump_txt = self.tcpdump_helper(
            mirror_host, tcpdump_filter, [
                lambda: first_host.cmd(first_ping_second)])
        self.assertTrue(re.search(
            '%s: ICMP echo request' % second_host.IP(), tcpdump_txt),
                        msg=tcpdump_txt)
        self.assertTrue(re.search(
            '%s: ICMP echo reply' % first_host.IP(), tcpdump_txt),
                        msg=tcpdump_txt)

    def verify_eapol_mirrored(self, first_host, second_host, mirror_host):
        self.net.ping((first_host, second_host))
        for host in (first_host, second_host):
            self.require_host_learned(host)
        self.assertEquals(0, self.net.ping((first_host, second_host)))
        mirror_mac = mirror_host.MAC()
        tmp_eap_conf = os.path.join(self.tmpdir, 'eap.conf')
        tcpdump_filter = (
            'not ether src %s and ether proto 0x888e' % mirror_mac)
        eap_conf_cmd = (
            'echo "eapol_version=2\nap_scan=0\nnetwork={\n'
            'key_mgmt=IEEE8021X\neap=MD5\nidentity=\\"login\\"\n'
            'password=\\"password\\"\n}\n" > %s' % tmp_eap_conf)
        wpa_supplicant_cmd = self.timeout_cmd(
            'wpa_supplicant -c%s -Dwired -i%s -d' % (
                tmp_eap_conf,
                first_host.defaultIntf().name),
            5)
        tcpdump_txt = self.tcpdump_helper(
            mirror_host, tcpdump_filter, [
                lambda: first_host.cmd(eap_conf_cmd),
                lambda: first_host.cmd(wpa_supplicant_cmd)])
        self.assertTrue(
            re.search('01:80:c2:00:00:03, ethertype EAPOL', tcpdump_txt),
            msg=tcpdump_txt)

    def bogus_mac_flooded_to_port1(self):
        first_host, second_host, third_host = self.net.hosts[0:3]
        unicast_flood_filter = 'ether host %s' % self.BOGUS_MAC
        static_bogus_arp = 'arp -s %s %s' % (first_host.IP(), self.BOGUS_MAC)
        curl_first_host = 'curl -m 5 http://%s' % first_host.IP()
        tcpdump_txt = self.tcpdump_helper(
            first_host, unicast_flood_filter,
            [lambda: second_host.cmd(static_bogus_arp),
             lambda: second_host.cmd(curl_first_host),
             lambda: self.net.ping(hosts=(second_host, third_host))])
        return not re.search('0 packets captured', tcpdump_txt)

    def verify_lldp_blocked(self):
        first_host, second_host = self.net.hosts[0:2]
        lldp_filter = 'ether proto 0x88cc'
        ladvd_mkdir = 'mkdir -p /var/run/ladvd'
        send_lldp = '%s -L -o %s' % (
            self.timeout_cmd(self.LADVD, 30),
            second_host.defaultIntf())
        tcpdump_txt = self.tcpdump_helper(
            first_host, lldp_filter,
            [lambda: second_host.cmd(ladvd_mkdir),
             lambda: second_host.cmd(send_lldp),
             lambda: second_host.cmd(send_lldp),
             lambda: second_host.cmd(send_lldp)],
            timeout=20, packets=5)
        if re.search(second_host.MAC(), tcpdump_txt):
            return False
        return True

    def is_cdp_blocked(self):
        first_host, second_host = self.net.hosts[0:2]
        cdp_filter = 'ether host 01:00:0c:cc:cc:cc and ether[20:2]==0x2000'
        ladvd_mkdir = 'mkdir -p /var/run/ladvd'
        send_cdp = '%s -C -o %s' % (
            self.timeout_cmd(self.LADVD, 30),
            second_host.defaultIntf())
        tcpdump_txt = self.tcpdump_helper(
            first_host,
            cdp_filter,
            [lambda: second_host.cmd(ladvd_mkdir),
             lambda: second_host.cmd(send_cdp),
             lambda: second_host.cmd(send_cdp),
             lambda: second_host.cmd(send_cdp)],
            timeout=20, packets=5)

        if re.search(second_host.MAC(), tcpdump_txt):
            return False
        return True

    def verify_hup_faucet(self, timeout=3):
        """HUP and verify the HUP was processed."""
        start_configure_count = self.get_configure_count()
        self.hup_faucet()
        for _ in range(timeout):
            configure_count = self.get_configure_count()
            if configure_count > start_configure_count:
                return
            time.sleep(1)
        self.fail('HUP not processed by FAUCET')

    def force_faucet_reload(self, new_config):
        """Force FAUCET to reload by adding new line to config file."""
        open(os.environ['FAUCET_CONFIG'], 'a').write(new_config)
        self.verify_hup_faucet()

    def get_host_port_stats(self, hosts_switch_ports):
        port_stats = {}
        for host, switch_port in hosts_switch_ports:
            port_stats[host] = self.get_port_stats_from_dpid(self.dpid, switch_port)
        return port_stats

    def of_bytes_mbps(self, start_port_stats, end_port_stats, var, seconds):
        return (end_port_stats[var] - start_port_stats[var]) * 8 / seconds / self.ONEMBPS

    def verify_iperf_min(self, hosts_switch_ports, min_mbps, server_ip):
        """Verify minimum performance and OF counters match iperf approximately."""
        seconds = 5
        prop = 0.1
        iperf_port, _ = faucet_mininet_test_util.find_free_port(
            self.ports_sock)
        start_port_stats = self.get_host_port_stats(hosts_switch_ports)
        hosts = []
        for host, _ in hosts_switch_ports:
            hosts.append(host)
        client_host, server_host = hosts
        iperf_mbps = self.iperf(
            client_host, server_host, server_ip, iperf_port, seconds)
        self.assertTrue(iperf_mbps > min_mbps)
        # TODO: account for drops.
        for _ in range(3):
            end_port_stats = self.get_host_port_stats(hosts_switch_ports)
            approx_match = True
            for host in hosts:
                of_rx_mbps = self.of_bytes_mbps(
                    start_port_stats[host], end_port_stats[host], 'rx_bytes', seconds)
                of_tx_mbps = self.of_bytes_mbps(
                    start_port_stats[host], end_port_stats[host], 'tx_bytes', seconds)
                print of_rx_mbps, of_tx_mbps
                max_of_mbps = float(max(of_rx_mbps, of_tx_mbps))
                iperf_to_max = iperf_mbps / max_of_mbps
                msg = 'iperf: %fmbps, of: %fmbps (%f)' % (
                    iperf_mbps, max_of_mbps, iperf_to_max)
                print(msg)
                if ((iperf_to_max < (1.0 - prop)) or
                        (iperf_to_max > (1.0 + prop))):
                    approx_match = False
            if approx_match:
                return
            time.sleep(1)
        self.fail(msg=msg)

    def curl_portmod(self, int_dpid, port_no, config, mask):
        """Use curl to send a portmod command via the ofctl module."""
        curl_format = ' '.join((
            'curl -X POST -d'
            '\'{"dpid": %s, "port_no": %u, "config": %u, "mask": %u}\'',
            '%s/stats/portdesc/modify'))
        return curl_format % (
            int_dpid, port_no, config, mask, self.ofctl_rest_url())

    def set_port_down(self, port_no):
        os.system(self.curl_portmod(
            self.dpid,
            port_no,
            ofp.OFPPC_PORT_DOWN,
            ofp.OFPPC_PORT_DOWN))

    def set_port_up(self, port_no):
        os.system(self.curl_portmod(
            self.dpid,
            port_no,
            0,
            ofp.OFPPC_PORT_DOWN))

    def wait_port_status(self, port_no, expected_status, timeout=10):
        for _ in range(timeout):
            port_status = self.scrape_prometheus_var(
                'port_status', {'port': port_no}, default=None)
            if port_status is not None and port_status == expected_status:
                return
            time.sleep(1)
        self.fail('port %s status %s != expected %u' % (
            port_no, port_status, expected_status))

    def wait_dp_status(self, expected_status, timeout=10):
        for _ in range(timeout):
            dp_status = self.scrape_prometheus_var(
                'dp_status', {}, default=None)
            if dp_status is not None and dp_status == expected_status:
                return
            time.sleep(1)
        self.fail('DP status %s != expected %u' % (
            dp_status, expected_status))

    def flap_all_switch_ports(self, flap_time=1):
        """Flap all ports on switch."""
        port_count = self.N_TAGGED + self.N_UNTAGGED
        for port_no in list(sorted(self.port_map.values()))[:port_count]:
            self.set_port_down(port_no)
            self.wait_port_status(port_no, 0)
            time.sleep(flap_time)
            self.set_port_up(port_no)
            self.wait_port_status(port_no, 1)

    def add_host_ipv6_address(self, host, ip_v6):
        """Add an IPv6 address to a Mininet host."""
        self.assertEquals(
            '',
            host.cmd('ip -6 addr add %s dev %s' % (ip_v6, host.intf())))

    def add_host_route(self, host, ip_dst, ip_gw):
        """Add an IP route to a Mininet host."""
        host.cmd('ip -%u route del %s' % (
            ip_dst.version, ip_dst.network.with_prefixlen))
        add_cmd = 'ip -%u route add %s via %s' % (
            ip_dst.version, ip_dst.network.with_prefixlen, ip_gw)
        results = host.cmd(add_cmd)
        self.assertEquals(
            '', results, msg='%s: %s' % (add_cmd, results))

    def _one_ip_ping(self, host, ping_cmd, retries, require_host_learned):
        if require_host_learned:
            self.require_host_learned(host)
        for _ in range(retries):
            ping_result = host.cmd(ping_cmd)
            if re.search(self.ONE_GOOD_PING, ping_result):
                return
        self.assertTrue(
            re.search(self.ONE_GOOD_PING, ping_result),
            msg='%s: %s' % (ping_cmd, ping_result))

    def one_ipv4_ping(self, host, dst, retries=3, require_host_learned=True, intf=None):
        """Ping an IPv4 destination from a host."""
        if intf is None:
            intf = host.defaultIntf()
        ping_cmd = 'ping -c1 -I%s %s' % (intf, dst)
        return self._one_ip_ping(host, ping_cmd, retries, require_host_learned)

    def one_ipv4_controller_ping(self, host):
        """Ping the controller from a host with IPv4."""
        self.one_ipv4_ping(host, self.FAUCET_VIPV4.ip)
        self.verify_ipv4_host_learned_mac(
            host, self.FAUCET_VIPV4.ip, self.FAUCET_MAC)

    def one_ipv6_ping(self, host, dst, retries=3):
        """Ping an IPv6 destination from a host."""
        ping_cmd = 'ping6 -c1 %s' % dst
        return self._one_ip_ping(host, ping_cmd, retries, require_host_learned=True)

    def one_ipv6_controller_ping(self, host):
        """Ping the controller from a host with IPv6."""
        self.one_ipv6_ping(host, self.FAUCET_VIPV6.ip)
        self.verify_ipv6_host_learned_mac(
            host, self.FAUCET_VIPV6.ip, self.FAUCET_MAC)

    def wait_for_tcp_listen(self, host, port, timeout=10, ipv=4):
        """Wait for a host to start listening on a port."""
        fuser_cmd = 'fuser -%u -n tcp %u' % (ipv, port)
        for _ in range(timeout):
            fuser_out = host.cmd(fuser_cmd)
            for fuser_line in fuser_out.splitlines():
                if re.search(r'^%u\/tcp:.+$' % port, fuser_line):
                    return
            time.sleep(1)
        self.fail('%s never listened on port %u (%s: %s)' % (
            host, port, fuser_cmd, fuser_out))

    def serve_hello_on_tcp_port(self, host, port):
        """Serve 'hello' on a TCP port on a host."""
        host.cmd(self.timeout_cmd('echo hello | nc -l %s %u &' % (host.IP(), port), 10))
        self.wait_for_tcp_listen(host, port)

    def wait_nonzero_packet_count_flow(self, exp_flow, timeout=10):
        """Wait for a flow to be present and have a non-zero packet_count."""
        for _ in range(timeout):
            flow = self.get_matching_flow(exp_flow, timeout=1)
            if flow and flow['packet_count'] > 0:
                return
            time.sleep(1)
        if flow:
            self.fail('flow %s matching %s had zero packet count' % (flow, exp_flow))
        else:
            self.fail('no flow matching %s' % exp_flow)

    def verify_tp_dst_blocked(self, port, first_host, second_host):
        """Verify that a TCP port on a host is blocked from another host."""
        self.serve_hello_on_tcp_port(second_host, port)
        self.assertEquals(
            '', first_host.cmd(self.timeout_cmd('nc %s %u' % (second_host.IP(), port), 10)))
        self.wait_nonzero_packet_count_flow(r'"tp_dst": %u' % port)

    def verify_tp_dst_notblocked(self, port, first_host, second_host):
        """Verify that a TCP port on a host is NOT blocked from another host."""
        self.serve_hello_on_tcp_port(second_host, port)
        self.assertEquals(
            'hello\r\n',
            first_host.cmd('nc -w 5 %s %u' % (second_host.IP(), port)))
        self.wait_nonzero_packet_count_flow(r'"tp_dst": %u' % port)

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
        exabgp_env = ' '.join((
            'exabgp.tcp.bind="%s"' % listen_address,
            'exabgp.tcp.port=%u' % port,
            'exabgp.log.all=true',
            'exabgp.log.routes=true',
            'exabgp.log.rib=true',
            'exabgp.log.packets=true',
            'exabgp.log.parser=true',
        ))
        open(exabgp_conf_file, 'w').write(exabgp_conf)
        controller = self.get_controller()
        exabgp_cmd = self.timeout_cmd(
            'exabgp %s -d 2> %s > %s &' % (
                exabgp_conf_file, exabgp_err, exabgp_log), 600)
        controller.cmd('env %s %s' % (exabgp_env, exabgp_cmd))
        self.wait_for_tcp_listen(
            controller, port,
            ipv=ipaddress.ip_address(unicode(listen_address)).version)
        return exabgp_log

    def wait_bgp_up(self, neighbor, vlan):
        """Wait for BGP to come up."""
        label_values = {
            'neighbor': neighbor,
            'vlan': vlan,
        }
        for _ in range(60):
            uptime = self.scrape_prometheus_var(
                'bgp_neighbor_uptime', label_values, default=0)
            if uptime > 0:
                return
            time.sleep(1)
        self.fail('exabgp did not peer with FAUCET')

    def stop_exabgp(self, port=179):
        """Stop exabgp process on controller host."""
        controller = self.get_controller()
        self.signal_proc_on_port(controller, port, 9)

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

    def wait_for_route_as_flow(self, nexthop, prefix, timeout=10,
                               with_group_table=False, nonzero_packets=False):
        """Verify a route has been added as a flow."""
        exp_prefix = '%s/%s' % (
            prefix.network_address, prefix.netmask)
        if prefix.version == 6:
            nw_dst_match = '"ipv6_dst": "%s"' % exp_prefix
        else:
            nw_dst_match = '"nw_dst": "%s"' % exp_prefix
        if with_group_table:
            group_id = self.get_group_id_for_matching_flow(nw_dst_match)
            self.wait_matching_in_group_table(
                'SET_FIELD: {eth_dst:%s}' % nexthop,
                group_id, timeout)
        else:
            exp_flow = 'SET_FIELD: {eth_dst:%s}.+%s' % (nexthop, nw_dst_match)
            if nonzero_packets:
                self.wait_nonzero_packet_count_flow(exp_flow, timeout)
            else:
                self.wait_until_matching_flow(exp_flow, timeout)

    def host_ipv4_alias(self, host, alias_ip):
        """Add an IPv4 alias address to a host."""
        del_cmd = 'ip addr del %s dev %s' % (
            alias_ip.with_prefixlen, host.intf())
        add_cmd = 'ip addr add %s dev %s label %s:1' % (
            alias_ip.with_prefixlen, host.intf(), host.intf())
        host.cmd(del_cmd)
        self.assertEquals('', host.cmd(add_cmd))

    def _verify_host_learned_mac(self, host, ip, ip_ver, mac, retries):
        for _ in range(retries):
            neighbors = host.cmd('ip -%u neighbor show' % ip_ver)
            for neighbor_line in neighbors.splitlines():
                neighbor_fields = neighbor_line.strip().split(' ')
                learned_ip = neighbor_fields[0]
                learned_mac = neighbor_fields[4]
                if learned_ip == str(ip) and learned_mac == mac:
                    return
            time.sleep(1)
        self.fail(
            'could not verify %s resolved to %s (%s)' % (ip, mac, neighbors))

    def verify_ipv4_host_learned_mac(self, host, ip, mac, retries=3):
        self._verify_host_learned_mac(host, ip, 4, mac, retries)

    def verify_ipv4_host_learned_host(self, host, learned_host):
        learned_ip = ipaddress.ip_interface(unicode(self.host_ipv4(learned_host)))
        self.verify_ipv4_host_learned_mac(host, learned_ip.ip, learned_host.MAC())

    def verify_ipv6_host_learned_mac(self, host, ip6, mac, retries=3):
        self._verify_host_learned_mac(host, ip6, 6, mac, retries)

    def verify_ipv6_host_learned_host(self, host, learned_host):
        learned_ip6 = ipaddress.ip_interface(unicode(self.host_ipv6(learned_host)))
        self.verify_ipv6_host_learned_mac(host, learned_ip6.ip, learned_host.MAC())

    def iperf_client(self, client_host, iperf_client_cmd):
        for _ in range(3):
            iperf_results = client_host.cmd(iperf_client_cmd)
            iperf_csv = iperf_results.strip().split(',')
            if len(iperf_csv) == 9:
                return int(iperf_csv[-1]) / self.ONEMBPS
            time.sleep(1)
        self.fail('%s: %s' % (iperf_client_cmd, iperf_results))

    def iperf(self, client_host, server_host, server_ip, port, seconds):
        iperf_base_cmd = 'iperf -f M -p %u' % port
        if server_ip.version == 6:
            iperf_base_cmd += ' -V'
        iperf_server_cmd = '%s -s' % iperf_base_cmd
        iperf_server_cmd = self.timeout_cmd(
            iperf_server_cmd, (seconds * 3) + 5)
        iperf_client_cmd = self.timeout_cmd(
            '%s -y c -c %s -t %u' % (iperf_base_cmd, server_ip, seconds),
            seconds + 5)
        server_start_exp = r'Server listening on TCP port %u' % port
        for _ in range(3):
            server_out = server_host.popen(
                iperf_server_cmd, stderr=subprocess.STDOUT)
            popens = {server_host: server_out}
            lines = []
            for host, line in pmonitor(popens):
                if host == server_host:
                    lines.append(line)
                    if re.search(server_start_exp, line):
                        self.wait_for_tcp_listen(
                            server_host, port, ipv=server_ip.version)
                        iperf_mbps = self.iperf_client(
                            client_host, iperf_client_cmd)
                        self.signal_proc_on_port(server_host, port, 9)
                        return iperf_mbps
            time.sleep(1)
        self.fail('%s never started (%s, %s)' % (
            iperf_server_cmd, server_start_exp, ' '.join(lines)))

    def verify_ipv4_routing(self, first_host, first_host_routed_ip,
                            second_host, second_host_routed_ip,
                            with_group_table=False):
        """Verify one host can IPV4 route to another via FAUCET."""
        self.host_ipv4_alias(first_host, first_host_routed_ip)
        self.host_ipv4_alias(second_host, second_host_routed_ip)
        self.add_host_route(
            first_host, second_host_routed_ip, self.FAUCET_VIPV4.ip)
        self.add_host_route(
            second_host, first_host_routed_ip, self.FAUCET_VIPV4.ip)
        self.net.ping(hosts=(first_host, second_host))
        self.wait_for_route_as_flow(
            first_host.MAC(), first_host_routed_ip.network,
            with_group_table=with_group_table)
        self.wait_for_route_as_flow(
            second_host.MAC(), second_host_routed_ip.network,
            with_group_table=with_group_table)
        self.one_ipv4_ping(first_host, second_host_routed_ip.ip)
        self.one_ipv4_ping(second_host, first_host_routed_ip.ip)
        self.verify_ipv4_host_learned_host(first_host, second_host)
        self.verify_ipv4_host_learned_host(second_host, first_host)
        # verify at least 1M iperf
        for client_host, server_host, server_ip in (
                (first_host, second_host, second_host_routed_ip.ip),
                (second_host, first_host, first_host_routed_ip.ip)):
            iperf_port, _ = faucet_mininet_test_util.find_free_port(
                self.ports_sock)
            iperf_mbps = self.iperf(
                client_host, server_host, server_ip, iperf_port, 5)
            print('%u mbps to %s' % (iperf_mbps, server_ip))
            self.assertGreater(iperf_mbps, 1)
        # verify packets matched routing flows
        self.wait_for_route_as_flow(
            first_host.MAC(), first_host_routed_ip.network,
            with_group_table=with_group_table,
            nonzero_packets=True)
        self.wait_for_route_as_flow(
            second_host.MAC(), second_host_routed_ip.network,
            with_group_table=with_group_table,
            nonzero_packets=True)

    def verify_ipv4_routing_mesh(self, with_group_table=False):
        """Verify hosts can route to each other via FAUCET."""
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_routed_ip = ipaddress.ip_interface(u'10.0.1.1/24')
        second_host_routed_ip = ipaddress.ip_interface(u'10.0.2.1/24')
        second_host_routed_ip2 = ipaddress.ip_interface(u'10.0.3.1/24')
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip,
            with_group_table=with_group_table)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip2,
            with_group_table=with_group_table)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip,
            with_group_table=with_group_table)
        self.verify_ipv4_routing(
            first_host, first_host_routed_ip,
            second_host, second_host_routed_ip2,
            with_group_table=with_group_table)

    def setup_ipv6_hosts_addresses(self, first_host, first_host_ip,
                                   first_host_routed_ip, second_host,
                                   second_host_ip, second_host_routed_ip):
        """Configure host IPv6 addresses for testing."""
        for host in first_host, second_host:
            host.cmd('ip -6 addr flush dev %s' % host.intf())
        self.add_host_ipv6_address(first_host, first_host_ip)
        self.add_host_ipv6_address(second_host, second_host_ip)
        self.add_host_ipv6_address(first_host, first_host_routed_ip)
        self.add_host_ipv6_address(second_host, second_host_routed_ip)
        for host in first_host, second_host:
            self.require_host_learned(host)

    def verify_ipv6_routing(self, first_host, first_host_ip,
                            first_host_routed_ip, second_host,
                            second_host_ip, second_host_routed_ip,
                            with_group_table=False):
        """Verify one host can IPV6 route to another via FAUCET."""
        self.one_ipv6_ping(first_host, second_host_ip.ip)
        self.one_ipv6_ping(second_host, first_host_ip.ip)
        self.add_host_route(
            first_host, second_host_routed_ip, self.FAUCET_VIPV6.ip)
        self.add_host_route(
            second_host, first_host_routed_ip, self.FAUCET_VIPV6.ip)
        self.wait_for_route_as_flow(
            first_host.MAC(), first_host_routed_ip.network,
            with_group_table=with_group_table)
        self.wait_for_route_as_flow(
            second_host.MAC(), second_host_routed_ip.network,
            with_group_table=with_group_table)
        self.one_ipv6_controller_ping(first_host)
        self.one_ipv6_controller_ping(second_host)
        self.one_ipv6_ping(first_host, second_host_routed_ip.ip)
        # verify at least 1M iperf
        for client_host, server_host, server_ip in (
                (first_host, second_host, second_host_routed_ip.ip),
                (second_host, first_host, first_host_routed_ip.ip)):
            iperf_port, _ = faucet_mininet_test_util.find_free_port(
                self.ports_sock)
            iperf_mbps = self.iperf(
                client_host, server_host, server_ip, iperf_port, 5)
            print('%u mbps to %s' % (iperf_mbps, server_ip))
            self.assertGreater(iperf_mbps, 1)
        self.one_ipv6_ping(first_host, second_host_ip.ip)
        self.verify_ipv6_host_learned_mac(
            first_host, second_host_ip.ip, second_host.MAC())
        self.one_ipv6_ping(second_host, first_host_ip.ip)
        self.verify_ipv6_host_learned_mac(
            second_host, first_host_ip.ip, first_host.MAC())

    def verify_ipv6_routing_pair(self, first_host, first_host_ip,
                                 first_host_routed_ip, second_host,
                                 second_host_ip, second_host_routed_ip,
                                 with_group_table=False):
        """Verify hosts can route IPv6 to each other via FAUCET."""
        self.setup_ipv6_hosts_addresses(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip)
        self.verify_ipv6_routing(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip,
            with_group_table=with_group_table)

    def verify_ipv6_routing_mesh(self, with_group_table=False):
        """Verify IPv6 routing between hosts and multiple subnets."""
        host_pair = self.net.hosts[:2]
        first_host, second_host = host_pair
        first_host_ip = ipaddress.ip_interface(u'fc00::1:1/112')
        second_host_ip = ipaddress.ip_interface(u'fc00::1:2/112')
        first_host_routed_ip = ipaddress.ip_interface(u'fc00::10:1/112')
        second_host_routed_ip = ipaddress.ip_interface(u'fc00::20:1/112')
        second_host_routed_ip2 = ipaddress.ip_interface(u'fc00::30:1/112')
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip,
            with_group_table=with_group_table)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2,
            with_group_table=with_group_table)
        self.swap_host_macs(first_host, second_host)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip,
            with_group_table=with_group_table)
        self.verify_ipv6_routing_pair(
            first_host, first_host_ip, first_host_routed_ip,
            second_host, second_host_ip, second_host_routed_ip2,
            with_group_table=with_group_table)

    def verify_invalid_bgp_route(self, pattern):
        """Check if we see the pattern in Faucet's log"""
        controller = self.get_controller()
        count = controller.cmd(
            'grep -c "%s" %s' % (pattern, os.environ['FAUCET_LOG']))
        self.assertGreater(count, 0)
