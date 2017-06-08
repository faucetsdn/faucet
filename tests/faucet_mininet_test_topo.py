"""Topology components for FAUCET Mininet unit tests."""

import os
import socket
import string

import netifaces

from mininet.topo import Topo
from mininet.node import Controller
from mininet.node import Host
from mininet.node import OVSSwitch

import faucet_mininet_test_util


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
        for cmd in (
                'ip -4 addr flush dev %s' % intf,
                'ip -6 addr flush dev %s' % intf,
                'vconfig add %s %d' % (intf, vlan),
                'ip link set dev %s up' % vlan_intf_name,
                'ip -4 addr add %s dev %s' % (params['ip'], vlan_intf_name)):
            self.cmd(cmd)
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

    def build(self, ports_sock, dpid=0, n_tagged=0, tagged_vid=100, n_untagged=0,
              test_name=None):
        port, ports_served = faucet_mininet_test_util.find_free_port(
            ports_sock, test_name)
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

    def build(self, ports_sock, dpid=0, n_tagged=0, tagged_vid=100, n_untagged=0,
              test_name=None):
        port, ports_served = faucet_mininet_test_util.find_free_port(
            ports_sock, test_name)
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


class FaucetStringOfDPSwitchTopo(FaucetSwitchTopo):

    def build(self, ports_sock, dpids, n_tagged=0, tagged_vid=100, n_untagged=0,
              test_name=None):
        """String of datapaths each with hosts with a single FAUCET controller.

                               Hosts
                               ||||
                               ||||
                 +----+       +----+       +----+
              ---+1   |       |1234|       |   1+---
        Hosts ---+2   |       |    |       |   2+--- Hosts
              ---+3   |       |    |       |   3+---
              ---+4  5+-------+5  6+-------+5  4+---
                 +----+       +----+       +----+

                 Faucet-1     Faucet-2     Faucet-3

                   |            |            |
                   |            |            |
                   +-------- controller -----+

        * s switches (above S = 3; for S > 3, switches are added to the chain)
        * (n_tagged + n_untagged) hosts per switch
        * (n_tagged + n_untagged + 1) links on switches 0 and s-1,
          with final link being inter-switch
        * (n_tagged + n_untagged + 2) links on switches 0 < n < s-1,
          with final two links being inter-switch
        """
        last_switch = None
        for dpid in dpids:
            port, ports_served = faucet_mininet_test_util.find_free_port(
                ports_sock, test_name)
            sid_prefix = self._get_sid_prefix(ports_served)
            hosts = []
            for host_n in range(n_tagged):
                hosts.append(self._add_tagged_host(sid_prefix, tagged_vid, host_n))
            for host_n in range(n_untagged):
                hosts.append(self._add_untagged_host(sid_prefix, host_n))
            switch = self._add_faucet_switch(sid_prefix, port, dpid)
            for host in hosts:
                self.addLink(host, switch)
            # Add a switch-to-switch link with the previous switch,
            # if this isn't the first switch in the topology.
            if last_switch is not None:
                self.addLink(last_switch, switch)
            last_switch = switch


class BaseFAUCET(Controller):

    controller_intf = None
    tmpdir = None
    BASE_CARGS = ' '.join((
        '--verbose',
        '--use-stderr',
        '--ofp-tcp-listen-port=%s'))

    def __init__(self, name, tmpdir, controller_intf=None, cargs='', **kwargs):
        name = '%s-%u' % (name, os.getpid())
        self.tmpdir = tmpdir
        self.controller_intf = controller_intf
        super(BaseFAUCET, self).__init__(
            name, cargs=self._add_cargs(cargs), **kwargs)

    def _add_cargs(self, cargs):
        ipv4_host = ''
        if self.controller_intf is not None:
            # pylint: disable=no-member
            ipv4_host = '--ofp-listen-host=%s' % netifaces.ifaddresses(
                self.controller_intf)[socket.AF_INET][0]['addr']
        return ' '.join((self.BASE_CARGS, ipv4_host, cargs))

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

    def _command(self, env, tmpdir, name, args):
        script_wrapper_name = os.path.join(tmpdir, 'start-%s.sh' % name)
        script_wrapper = open(script_wrapper_name, 'w')
        env_vars = []
        for var, val in list(sorted(env.items())):
            env_vars.append('='.join((var, val)))
        script_wrapper.write(
            'PYTHONPATH=.:..:../faucet %s exec ryu-manager %s $*\n' % (
                ' '.join(env_vars), args))
        script_wrapper.close()
        return '/bin/sh %s' % script_wrapper_name

    def start(self):
        self._start_tcpdump()
        super(BaseFAUCET, self).start()


class FAUCET(BaseFAUCET):
    """Start a FAUCET controller."""

    def __init__(self, name, tmpdir, controller_intf, env,
                 ctl_privkey, ctl_cert, ca_certs,
                 ports_sock, port, test_name, **kwargs):
        self.ofctl_port, _ = faucet_mininet_test_util.find_free_port(
            ports_sock, test_name)
        cargs = ' '.join((
            '--wsapi-host=127.0.0.1',
            '--wsapi-port=%u' % self.ofctl_port,
            self._tls_cargs(port, ctl_privkey, ctl_cert, ca_certs)))
        super(FAUCET, self).__init__(
            name,
            tmpdir,
            controller_intf,
            cargs=cargs,
            command=self._command(env, tmpdir, name, 'ryu.app.ofctl_rest faucet.faucet'),
            port=port,
            **kwargs)


class Gauge(BaseFAUCET):
    """Start a Gauge controller."""

    def __init__(self, name, tmpdir, controller_intf, env,
                 ctl_privkey, ctl_cert, ca_certs,
                 port, **kwargs):
        super(Gauge, self).__init__(
            name,
            tmpdir,
            controller_intf,
            cargs=self._tls_cargs(port, ctl_privkey, ctl_cert, ca_certs),
            command=self._command(env, tmpdir, name, 'faucet.gauge'),
            port=port,
            **kwargs)


class FaucetAPI(BaseFAUCET):
    """Start a controller to run the Faucet API tests."""

    def __init__(self, name, tmpdir, env, **kwargs):
        super(FaucetAPI, self).__init__(
            name,
            tmpdir,
            command=self._command(env, tmpdir, name, 'faucet.faucet test_api.py'),
            **kwargs)
