"""Topology components for FAUCET Mininet unit tests."""

import string

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

    def _command(self, args):
        return 'PYTHONPATH=../ ryu-manager %s' % args

    def start(self):
        self._start_tcpdump()
        super(BaseFAUCET, self).start()
