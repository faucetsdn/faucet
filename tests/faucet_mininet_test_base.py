#!/usr/bin/env python

"""Base class for all FAUCET unit tests."""

# pylint: disable=missing-docstring

import collections
import json
import os
import random
import re
import shutil
import subprocess
import tempfile
import time
import unittest
import yaml

import ipaddress
import requests

from requests.exceptions import ConnectionError

from mininet.net import Mininet
from mininet.node import Intf
from mininet.util import dumpNodeConnections, pmonitor
from ryu.ofproto import ofproto_v1_3 as ofp

import faucet_mininet_test_util
import faucet_mininet_test_topo


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
    GAUGE_CONFIG = ''

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
    config_ports = {'bgp_port': None}
    env = collections.defaultdict(dict)
    rand_dpids = set()


    def __init__(self, name, config, root_tmpdir, ports_sock):
        super(FaucetTestBase, self).__init__(name)
        self.config = config
        self.root_tmpdir = root_tmpdir
        self.ports_sock = ports_sock

    def rand_dpid(self):
        reserved_range = 100
        while True:
            dpid = random.randint(1, (2**32 - reserved_range)) + reserved_range
            if dpid not in self.rand_dpids:
                self.rand_dpids.add(dpid)
                return str(dpid)

    def _set_var(self, controller, var, value):
        self.env[controller][var] = value

    def _set_var_path(self, controller, var, path):
        self._set_var(controller, var, os.path.join(self.tmpdir, path))

    def _set_prom_port(self, name='faucet'):
        prom_port, _ = faucet_mininet_test_util.find_free_port(
            self.ports_sock, self._test_name())
        self._set_var(name, 'FAUCET_PROMETHEUS_PORT', str(prom_port))
        self._set_var(name, 'FAUCET_PROMETHEUS_ADDR', u'127.0.0.1')

    def _set_vars(self):
        self._set_var_path('faucet', 'FAUCET_CONFIG', 'faucet.yaml')
        self._set_var_path('faucet', 'FAUCET_LOG', 'faucet.log')
        self._set_var_path('faucet', 'FAUCET_EXCEPTION_LOG', 'faucet-exception.log')
        self._set_var_path('gauge', 'GAUGE_CONFIG', 'gauge.yaml')
        self._set_var_path('gauge', 'GAUGE_LOG', 'gauge.log')
        self._set_var_path('gauge', 'GAUGE_EXCEPTION_LOG', 'gauge-exception.log')
        self.faucet_config_path = self.env['faucet']['FAUCET_CONFIG']
        self.gauge_config_path = self.env['gauge']['GAUGE_CONFIG']
        self._set_prom_port()
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

    def _write_controller_configs(self):
        self.CONFIG = '\n'.join((
            self.get_config_header(
                self.CONFIG_GLOBAL, self.debug_log_path, self.dpid, self.hardware),
            self.CONFIG % self.port_map))
        for port_name in list(self.config_ports.keys()):
            if re.search(port_name, self.CONFIG):
                port, _ = faucet_mininet_test_util.find_free_port(
                    self.ports_sock, self._test_name())
                self.CONFIG = self.CONFIG % {'bgp_port': port}
                self.config_ports[port_name] = port
                print('allocating port %u for %s' % (port, port_name))
        open(self.faucet_config_path, 'w').write(self.CONFIG)
        self.influx_port, _ = faucet_mininet_test_util.find_free_port(
            self.ports_sock, self._test_name())
        self.GAUGE_CONFIG = self.get_gauge_config(
            self.faucet_config_path,
            self.monitor_stats_file,
            self.monitor_state_file,
            self.monitor_flow_table_file,
            self.influx_port)
        open(self.gauge_config_path, 'w').write(self.GAUGE_CONFIG)

    def _test_name(self):
        return '-'.join(self.id().split('.')[1:])

    def _tmpdir_name(self):
        return tempfile.mkdtemp(
            prefix='%s-' % self._test_name(), dir=self.root_tmpdir)

    def _controller_lognames(self):
        lognames = []
        for controller in self.net.controllers:
            logname = '/tmp/%s.log' % controller.name
            if os.path.exists(logname) and os.path.getsize(logname) > 0:
                lognames.append(logname)
        return lognames

    def setUp(self):
        self.tmpdir = self._tmpdir_name()
        self._set_vars()

        if self.hw_switch:
            self.topo_class = faucet_mininet_test_topo.FaucetHwSwitchTopo
            self.dpid = faucet_mininet_test_util.str_int_dpid(self.dpid)
        else:
            self.topo_class = faucet_mininet_test_topo.FaucetSwitchTopo
            self.dpid = self.rand_dpid()
            self.of_port, _ = faucet_mininet_test_util.find_free_port(
                self.ports_sock, self._test_name())
            self.gauge_of_port, _ = faucet_mininet_test_util.find_free_port(
                self.ports_sock, self._test_name())

        self._write_controller_configs()

    def tearDown(self):
        """Clean up after a test."""
        open(os.path.join(self.tmpdir, 'prometheus.log'), 'w').write(
            self.scrape_prometheus())
        logs = self._controller_lognames()
        if self.net is not None:
            self.net.stop()
        faucet_mininet_test_util.return_free_ports(
            self.ports_sock, self._test_name())
        # must not be any controller exception.
        self.verify_no_exception(self.env['faucet']['FAUCET_EXCEPTION_LOG'])
        # Associate controller log with test results, if we are keeping
        # the temporary directory, or effectively delete it if not.
        # mininet doesn't have a way to change its log name for the controller.
        for log in logs:
            shutil.move(log, self.tmpdir)
        for _, debug_log in self._get_ofchannel_logs():
            self.assertFalse(
                re.search('OFPErrorMsg', open(debug_log).read()),
                msg='debug log has OFPErrorMsgs')

    def _attach_physical_switch(self):
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
        self._start_faucet(controller_intf)
        self.pre_start_net()
        if self.hw_switch:
            self._attach_physical_switch()
        self._wait_debug_log()
        for port_no in self._dp_ports():
            self.set_port_up(port_no)
        dumpNodeConnections(self.net.hosts)

    def _get_controller(self):
        """Return the first (only) controller."""
        return self.net.controllers[0]

    def _start_faucet(self, controller_intf):
        for _ in range(3):
            self.net = Mininet(
                self.topo, controller=faucet_mininet_test_topo.FAUCET(
                    name='faucet', tmpdir=self.tmpdir,
                    controller_intf=controller_intf,
                    env=self.env['faucet'],
                    ctl_privkey=self.ctl_privkey,
                    ctl_cert=self.ctl_cert,
                    ca_certs=self.ca_certs,
                    ports_sock=self.ports_sock,
                    port=self.of_port,
                    test_name=self._test_name()))
            if self.RUN_GAUGE:
                gauge_controller = faucet_mininet_test_topo.Gauge(
                    name='gauge', tmpdir=self.tmpdir,
                    env=self.env['gauge'],
                    controller_intf=controller_intf,
                    ctl_privkey=self.ctl_privkey,
                    ctl_cert=self.ctl_cert,
                    ca_certs=self.ca_certs,
                    port=self.gauge_of_port)
                self.net.addController(gauge_controller)
            self.net.start()
            if (self._wait_controllers_logging() and
                    self.wait_dp_status(1) and
                    self._wait_until_ofctl_up()):
                return
            self.net.stop()
            time.sleep(1)
        self.fail('could not start FAUCET')

    def _ofctl_rest_url(self):
        """Return control URL for Ryu ofctl module."""
        return 'http://127.0.0.1:%u' % self._get_controller().ofctl_port

    def _ofctl(self, req):
        try:
            ofctl_result = requests.get(req).text
        except ConnectionError:
            return None
        return ofctl_result

    def _ofctl_up(self):
        switches = self._ofctl('%s/stats/switches' % self._ofctl_rest_url())
        return switches is not None and re.search(r'^\[[^\]]+\]$', switches)

    def _wait_until_ofctl_up(self, timeout=10):
        for _ in range(timeout):
            if self._ofctl_up():
                return True
            time.sleep(1)
        return False

    def _ofctl_get(self, int_dpid, req, timeout):
        for _ in range(timeout):
            ofctl_result = self._ofctl(req)
            if req is not None:
                try:
                    ofmsgs = json.loads(ofctl_result)[int_dpid]
                    return [json.dumps(ofmsg) for ofmsg in ofmsgs]
                except ValueError:
                    # Didn't get valid JSON, try again
                    time.sleep(1)
                    continue
        return []

    def _curl_portmod(self, int_dpid, port_no, config, mask):
        """Use curl to send a portmod command via the ofctl module."""
        curl_format = ' '.join((
            'curl -X POST -d'
            '\'{"dpid": %s, "port_no": %u, "config": %u, "mask": %u}\'',
            '%s/stats/portdesc/modify'))
        return curl_format % (
            int_dpid, port_no, config, mask, self._ofctl_rest_url())

    def _signal_proc_on_port(self, host, port, signal):
        tcp_pattern = '%s/tcp' % port
        fuser_out = host.cmd('fuser %s -k -%u' % (tcp_pattern, signal))
        return re.search(r'%s:\s+\d+' % tcp_pattern, fuser_out)

    def _get_ofchannel_logs(self):
        config = yaml.load(open(self.env['faucet']['FAUCET_CONFIG']))
        ofchannel_logs = []
        for dp_name, dp_config in config['dps'].items():
            if 'ofchannel_log' in dp_config:
                debug_log = dp_config['ofchannel_log']
                ofchannel_logs.append((dp_name, debug_log))
        return ofchannel_logs

    def _report_controller_log(self):
        self.verify_no_exception(self.env['faucet']['FAUCET_EXCEPTION_LOG'])
        controller_txt = ''
        for log in self._controller_lognames():
            controller_txt += open(log).read()
        return controller_txt

    def _wait_controllers_logging(self, timeout=10):
        controller_count = len(self.net.controllers)
        for _ in range(timeout):
            lognames_count = len(self._controller_lognames())
            if controller_count == lognames_count:
                return True
            time.sleep(1)
        return False

    def _wait_debug_log(self):
        """Require all switches to have exchanged flows with controller."""
        ofchannel_logs = self._get_ofchannel_logs()
        for _, debug_log in ofchannel_logs:
            for _ in range(60):
                if (os.path.exists(debug_log) and
                        os.path.getsize(debug_log) > 0):
                    return True
                time.sleep(1)
        return False

    def verify_no_exception(self, exception_log_name):
        if not os.path.exists(exception_log_name):
            return
        exception_contents = open(exception_log_name, 'r').read()
        self.assertEquals(
            '',
            exception_contents,
            msg='%s log contains %s' % (exception_log_name, exception_contents))

    def tcpdump_helper(self, tcpdump_host, tcpdump_filter, funcs=None,
                       vflags='-v', timeout=10, packets=2, root_intf=False):
        intf = tcpdump_host.intf().name
        if root_intf:
            intf = intf.split('.')[0]
        tcpdump_cmd = faucet_mininet_test_util.timeout_soft_cmd(
            'tcpdump -i %s -e -n -U %s -c %u %s' % (
                intf, vflags, packets, tcpdump_filter),
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
                    if funcs is not None:
                        for func in funcs:
                            func()
                else:
                    print('tcpdump_helper: %s' % line)
        self.assertTrue(tcpdump_started, msg='%s did not start' % tcpdump_cmd)
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

    def get_all_groups_desc_from_dpid(self, dpid, timeout=2):
        int_dpid = faucet_mininet_test_util.str_int_dpid(dpid)
        return self._ofctl_get(
            int_dpid,
            '%s/stats/groupdesc/%s' % (self._ofctl_rest_url(), int_dpid),
            timeout)

    def get_all_flows_from_dpid(self, dpid, timeout=10):
        """Return all flows from DPID."""
        int_dpid = faucet_mininet_test_util.str_int_dpid(dpid)
        return self._ofctl_get(
            int_dpid,
            '%s/stats/flow/%s' % (self._ofctl_rest_url(), int_dpid),
            timeout)

    def get_port_stats_from_dpid(self, dpid, port, timeout=2):
        """Return OFStats for a port."""
        int_dpid = faucet_mininet_test_util.str_int_dpid(dpid)
        port_stats = self._ofctl_get(
            int_dpid,
            '%s/stats/port/%s/%s' % (self._ofctl_rest_url(), int_dpid, port),
            timeout)
        if port_stats:
            return json.loads(port_stats[0])
        return None

    def wait_matching_in_group_table(self, action, group_id, timeout=10):
        groupdump = os.path.join(self.tmpdir, 'groupdump-%s.txt' % self.dpid)
        for _ in range(timeout):
            group_dump = self.get_all_groups_desc_from_dpid(self.dpid, 1)
            groupdump_file = open(groupdump, 'w')
            for group_desc in group_dump:
                group_dict = json.loads(group_desc)
                groupdump_file.write(str(group_dict) + '\n')
                if group_dict['group_id'] == group_id:
                    actions = set(group_dict['buckets'][0]['actions'])
                    if set([action]).issubset(actions):
                        return True
            time.sleep(1)
        return False

    def get_matching_flows_on_dpid(self, dpid, match, timeout=10, table_id=None,
                                   actions=None, match_exact=False):
        flowdump = os.path.join(self.tmpdir, 'flowdump-%s.txt' % dpid)
        for _ in range(timeout):
            flow_dicts = []
            flow_dump = self.get_all_flows_from_dpid(dpid)
            flowdump_file = open(flowdump, 'w')
            for flow in flow_dump:
                flow_dict = json.loads(flow)
                flowdump_file.write(str(flow_dict) + '\n')
                if (table_id is not None and
                        flow_dict['table_id'] != table_id):
                    continue
                if actions is not None:
                    if not set(actions).issubset(set(flow_dict['actions'])):
                        continue
                if match is not None:
                    if match_exact:
                        if match.items() != flow_dict['match'].items():
                            continue
                    elif not set(match.items()).issubset(set(flow_dict['match'].items())):
                        continue
                flow_dicts.append(flow_dict)
            if flow_dicts:
                return flow_dicts
            time.sleep(1)
        return flow_dicts

    def get_matching_flow_on_dpid(self, dpid, match, timeout=10, table_id=None,
                                  actions=None, match_exact=None):
        flow_dicts = self.get_matching_flows_on_dpid(
            dpid, match, timeout=timeout, table_id=table_id,
            actions=actions, match_exact=match_exact)
        if flow_dicts:
            return flow_dicts[0]
        else:
            return []

    def get_matching_flow(self, match, timeout=10, table_id=None,
                          actions=None, match_exact=None):
        return self.get_matching_flow_on_dpid(
            self.dpid, match, timeout=timeout, table_id=table_id,
            actions=actions, match_exact=match_exact)

    def get_group_id_for_matching_flow(self, match, timeout=10, table_id=None):
        for _ in range(timeout):
            flow_dict = self.get_matching_flow(
                match, timeout=timeout, table_id=table_id)
            if flow_dict:
                for action in flow_dict['actions']:
                    if action.startswith('GROUP'):
                        _, group_id = action.split(':')
                        return int(group_id)
            time.sleep(1)
        self.fail(
            'Cannot find group_id for matching flow %s' % match)

    def matching_flow_present_on_dpid(self, dpid, match, timeout=10, table_id=None,
                                      actions=None, match_exact=None):
        """Return True if matching flow is present on a DPID."""
        if self.get_matching_flow_on_dpid(
                dpid, match, timeout=timeout, table_id=table_id,
                actions=actions, match_exact=match_exact):
            return True
        return False

    def matching_flow_present(self, match, timeout=10, table_id=None,
                              actions=None, match_exact=None):
        """Return True if matching flow is present on default DPID."""
        return self.matching_flow_present_on_dpid(
            self.dpid, match, timeout=timeout, table_id=table_id,
            actions=actions, match_exact=match_exact)

    def wait_until_matching_flow(self, match, timeout=10, table_id=None,
                                 actions=None, match_exact=False):
        """Wait (require) for flow to be present on default DPID."""
        self.assertTrue(
            self.matching_flow_present(
                match, timeout=timeout, table_id=table_id,
                actions=actions, match_exact=match_exact),
            msg=match)

    def wait_until_controller_flow(self):
        self.wait_until_matching_flow(None, actions=[u'OUTPUT:CONTROLLER'])

    def mac_learned(self, mac, timeout=10):
        """Return True if a MAC has been learned on default DPID."""
        return self.matching_flow_present(
            {u'dl_src': u'%s' % mac}, timeout=timeout, table_id=3)

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
        broadcast = (ipaddress.ip_interface(
            unicode(host_ip_net)).network.broadcast_address)
        if broadcast.version == 6:
            ping_cmd = 'ping6'
        for _ in range(retries):
            if self.host_learned(host, timeout=1):
                return
            # stimulate host learning with a broadcast ping
            host.cmd('%s -i 0.2 -c 1 -b %s' % (ping_cmd, broadcast))
        self.fail('host %s could not be learned' % host)

    def get_prom_port(self):
        return int(self.env['faucet']['FAUCET_PROMETHEUS_PORT'])

    def get_prom_addr(self):
        return self.env['faucet']['FAUCET_PROMETHEUS_ADDR']

    def _prometheus_url(self):
        return 'http://%s:%u' % (
            self.get_prom_addr(), self.get_prom_port())

    def scrape_prometheus(self):
        try:
            prom_lines = requests.get(self._prometheus_url()).text.split('\n')
        except ConnectionError:
            return ''
        prom_vars = []
        for prom_line in prom_lines:
            if not prom_line.startswith('#'):
                prom_vars.append(prom_line)
        return '\n'.join(prom_vars)

    def scrape_prometheus_var(self, var, labels=None, default=None,
                              dpid=True, multiple=False):
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
        self.verify_no_exception(self.env['faucet']['FAUCET_EXCEPTION_LOG'])
        self.verify_no_exception(self.env['gauge']['GAUGE_EXCEPTION_LOG'])

    def prometheus_smoke_test(self):
        prom_out = self.scrape_prometheus()
        for nonzero_var in (
                r'of_packet_ins', r'of_flowmsgs_sent', r'of_dp_connections',
                r'faucet_config\S+name=\"flood\"'):
            self.assertTrue(
                re.search(r'%s\S+\s+[1-9]+' % nonzero_var, prom_out),
                msg=prom_out)
        for notpresent_var in (
                'of_errors', 'of_dp_disconnections'):
            self.assertIsNone(
                re.search(notpresent_var, prom_out), msg=prom_out)

    def get_configure_count(self):
        """Return the number of times FAUCET has processed a reload request."""
        for _ in range(3):
            count = self.scrape_prometheus_var(
                'faucet_config_reload_requests', default=None, dpid=False)
            if count is not None:
                return count
            time.sleep(1)
        self.fail('configure count stayed zero')

    def hup_faucet(self):
        """Send a HUP signal to the controller."""
        controller = self._get_controller()
        self.assertTrue(
            self._signal_proc_on_port(controller, controller.port, 1))

    def verify_vlan_flood_limited(self, vlan_first_host, vlan_second_host,
                                  other_vlan_host):
        """Verify that flooding doesn't cross VLANs."""
        for first_host, second_host in (
                (vlan_first_host, vlan_second_host),
                (vlan_second_host, vlan_first_host)):
            tcpdump_filter = 'ether host %s or ether host %s' % (
                first_host.MAC(), second_host.MAC())
            tcpdump_txt = self.tcpdump_helper(
                other_vlan_host, tcpdump_filter, [
                    lambda: first_host.cmd('arp -d %s' % second_host.IP()),
                    lambda: first_host.cmd('ping -c1 %s' % second_host.IP())],
                packets=1)
            self.assertTrue(
                re.search('0 packets captured', tcpdump_txt), msg=tcpdump_txt)

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
        wpa_supplicant_cmd = faucet_mininet_test_util.timeout_cmd(
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

    def verify_port1_unicast(self, unicast_status):
        # Unicast flooding rule for from port 1
        self.assertEquals(
            self.matching_flow_present(
                {u'dl_vlan': u'100', u'in_port': int(self.port_map['port_1'])},
                table_id=7,
                match_exact=True),
            unicast_status)
        #  Unicast flood rule exists that output to port 1
        self.assertEquals(
            self.matching_flow_present(
                {u'dl_vlan': u'100', u'in_port': int(self.port_map['port_2'])},
                table_id=7,
                actions=[u'OUTPUT:%u' % self.port_map['port_1']],
                match_exact=True),
            unicast_status)

    def verify_lldp_blocked(self):
        first_host, second_host = self.net.hosts[0:2]
        lldp_filter = 'ether proto 0x88cc'
        ladvd_mkdir = 'mkdir -p /var/run/ladvd'
        send_lldp = '%s -L -o %s' % (
            faucet_mininet_test_util.timeout_cmd(self.LADVD, 30),
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
            faucet_mininet_test_util.timeout_cmd(self.LADVD, 30),
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
        open(self.env['faucet']['FAUCET_CONFIG'], 'a').write(new_config)
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
            self.ports_sock, self._test_name())
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

    def set_port_down(self, port_no):
        self.assertEquals(0,
            os.system(self._curl_portmod(
                self.dpid,
                port_no,
                ofp.OFPPC_PORT_DOWN,
                ofp.OFPPC_PORT_DOWN)))

    def set_port_up(self, port_no):
        self.assertEquals(0,
            os.system(self._curl_portmod(
                self.dpid,
                port_no,
                0,
                ofp.OFPPC_PORT_DOWN)))

    def wait_port_status(self, port_no, expected_status, timeout=10):
        for _ in range(timeout):
            port_status = self.scrape_prometheus_var(
                'port_status', {'port': port_no}, default=None)
            if port_status is not None and port_status == expected_status:
                return
            time.sleep(1)
        self.fail('port %s status %s != expected %u' % (
            port_no, port_status, expected_status))

    def wait_dp_status(self, expected_status, timeout=60):
        for _ in range(timeout):
            dp_status = self.scrape_prometheus_var(
                'dp_status', {}, default=None)
            if dp_status is not None and dp_status == expected_status:
                return True
            time.sleep(1)
        return False

    def _dp_ports(self):
        port_count = self.N_TAGGED + self.N_UNTAGGED
        return list(sorted(self.port_map.values()))[:port_count]

    def flap_all_switch_ports(self, flap_time=1):
        """Flap all ports on switch."""
        for port_no in self._dp_ports():
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

    def tcp_port_free(self, host, port, ipv=4):
        fuser_cmd = 'fuser -%u -n tcp %u' % (ipv, port)
        fuser_out = host.cmd(fuser_cmd)
        if fuser_out:
            for fuser_line in fuser_out.splitlines():
                if re.search(r'^%u\/tcp:.+$' % port, fuser_line):
                    return fuser_out
        return None

    def wait_for_tcp_free(self, host, port, timeout=10, ipv=4):
        """Wait for a host to start listening on a port."""
        for _ in range(timeout):
            fuser_out = self.tcp_port_free(host, port, ipv)
            if fuser_out is None:
                return
            time.sleep(1)
        self.fail('%s busy on port %u (%s)' % (host, port, fuser_out))

    def wait_for_tcp_listen(self, host, port, timeout=10, ipv=4):
        """Wait for a host to start listening on a port."""
        for _ in range(timeout):
            fuser_out = self.tcp_port_free(host, port, ipv)
            if fuser_out is not None:
                return
            time.sleep(1)
        self.fail('%s never listened on port %u' % (host, port))

    def serve_hello_on_tcp_port(self, host, port):
        """Serve 'hello' on a TCP port on a host."""
        host.cmd(faucet_mininet_test_util.timeout_cmd(
            'echo hello | nc -l %s %u &' % (host.IP(), port), 10))
        self.wait_for_tcp_listen(host, port)

    def wait_nonzero_packet_count_flow(self, match, timeout=10, table_id=None, actions=None):
        """Wait for a flow to be present and have a non-zero packet_count."""
        for _ in range(timeout):
            flow = self.get_matching_flow(match, timeout=1, table_id=table_id, actions=actions)
            if flow and flow['packet_count'] > 0:
                return
            time.sleep(1)
        if flow:
            self.fail('flow %s matching %s had zero packet count' % (flow, match))
        else:
            self.fail('no flow matching %s' % match)

    def verify_tp_dst_blocked(self, port, first_host, second_host, table_id=0):
        """Verify that a TCP port on a host is blocked from another host."""
        self.serve_hello_on_tcp_port(second_host, port)
        self.assertEquals(
            '', first_host.cmd(faucet_mininet_test_util.timeout_cmd(
                'nc %s %u' % (second_host.IP(), port), 10)))
        if table_id is not None:
            self.wait_nonzero_packet_count_flow(
                {u'tp_dst': int(port)}, table_id=table_id)

    def verify_tp_dst_notblocked(self, port, first_host, second_host, table_id=0):
        """Verify that a TCP port on a host is NOT blocked from another host."""
        self.serve_hello_on_tcp_port(second_host, port)
        self.assertEquals(
            'hello\r\n',
            first_host.cmd('nc -w 5 %s %u' % (second_host.IP(), port)))
        if table_id is not None:
            self.wait_nonzero_packet_count_flow({u'tp_dst': int(port)},
                table_id=table_id)

    def swap_host_macs(self, first_host, second_host):
        """Swap the MAC addresses of two Mininet hosts."""
        first_host_mac = first_host.MAC()
        second_host_mac = second_host.MAC()
        first_host.setMAC(second_host_mac)
        second_host.setMAC(first_host_mac)

    def start_exabgp(self, exabgp_conf):
        """Start exabgp process on controller host."""
        exabgp_conf_file = os.path.join(self.tmpdir, 'exabgp.conf')
        exabgp_log = os.path.join(self.tmpdir, 'exabgp.log')
        exabgp_err = os.path.join(self.tmpdir, 'exabgp.err')
        exabgp_env = ' '.join((
            'exabgp.log.all=true',
            'exabgp.log.routes=true',
            'exabgp.log.rib=true',
            'exabgp.log.packets=true',
            'exabgp.log.parser=true',
        ))
        bgp_port = self.config_ports['bgp_port']
        exabgp_conf = exabgp_conf % {'bgp_port': bgp_port}
        open(exabgp_conf_file, 'w').write(exabgp_conf)
        controller = self._get_controller()
        exabgp_cmd = faucet_mininet_test_util.timeout_cmd(
            'exabgp %s -d 2> %s > %s &' % (
                exabgp_conf_file, exabgp_err, exabgp_log), 600)
        controller.cmd('env %s %s' % (exabgp_env, exabgp_cmd))
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

    def exabgp_updates(self, exabgp_log):
        """Verify that exabgp process has received BGP updates."""
        controller = self._get_controller()
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
        exp_prefix = u'%s/%s' % (
            prefix.network_address, prefix.netmask)
        if prefix.version == 6:
            nw_dst_match = {u'ipv6_dst': exp_prefix}
            table_id = 5
        else:
            nw_dst_match = {u'nw_dst': exp_prefix}
            table_id = 4
        nexthop_action = u'SET_FIELD: {eth_dst:%s}' % nexthop
        if with_group_table:
            group_id = self.get_group_id_for_matching_flow(
                nw_dst_match)
            self.wait_matching_in_group_table(
                nexthop_action, group_id, timeout)
        else:
            if nonzero_packets:
                self.wait_nonzero_packet_count_flow(
                    nw_dst_match, timeout=timeout, table_id=table_id,
                    actions=[nexthop_action])
            else:
                self.wait_until_matching_flow(
                    nw_dst_match, timeout=timeout, table_id=table_id,
                    actions=[nexthop_action])

    def host_ipv4_alias(self, host, alias_ip):
        """Add an IPv4 alias address to a host."""
        del_cmd = 'ip addr del %s dev %s' % (
            alias_ip.with_prefixlen, host.intf())
        add_cmd = 'ip addr add %s dev %s label %s:1' % (
            alias_ip.with_prefixlen, host.intf(), host.intf())
        host.cmd(del_cmd)
        self.assertEquals('', host.cmd(add_cmd))

    def _verify_host_learned_mac(self, host, ipa, ip_ver, mac, retries):
        for _ in range(retries):
            neighbors = host.cmd('ip -%u neighbor show' % ip_ver)
            for neighbor_line in neighbors.splitlines():
                neighbor_fields = neighbor_line.strip().split(' ')
                learned_ipa = neighbor_fields[0]
                learned_mac = neighbor_fields[4]
                if learned_ipa == str(ipa) and learned_mac == mac:
                    return
            time.sleep(1)
        self.fail(
            'could not verify %s resolved to %s (%s)' % (ipa, mac, neighbors))

    def verify_ipv4_host_learned_mac(self, host, ipa, mac, retries=3):
        self._verify_host_learned_mac(host, ipa, 4, mac, retries)

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
        iperf_server_cmd = '%s -s -B %s' % (iperf_base_cmd, server_ip)
        iperf_server_cmd = faucet_mininet_test_util.timeout_cmd(
            iperf_server_cmd, (seconds * 3) + 5)
        iperf_client_cmd = faucet_mininet_test_util.timeout_cmd(
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
                        self._signal_proc_on_port(server_host, port, 9)
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
                self.ports_sock, self._test_name())
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
                self.ports_sock, self._test_name())
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
        controller = self._get_controller()
        count = controller.cmd(
            'grep -c "%s" %s' % (pattern, self.env['faucet']['FAUCET_LOG']))
        self.assertGreater(count, 0)
