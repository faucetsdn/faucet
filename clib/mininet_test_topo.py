#!/usr/bin/env python3
"""Topology components for FAUCET Mininet unit tests."""

from collections import namedtuple
import os
import socket
import string
import shutil
import subprocess
import time

import netifaces

# pylint: disable=too-many-arguments

from mininet.log import output, warn
from mininet.topo import Topo
from mininet.node import Controller
from mininet.node import CPULimitedHost
from mininet.node import OVSSwitch
from mininet.link import TCIntf, Link

from clib import mininet_test_util


SWITCH_START_PORT = 5


class FaucetIntf(TCIntf):
    """TCIntf that doesn't complain unnecessarily"""

    def delete(self):
        """Ignore interface deletion failure;
           this is common after a veth pair has been deleted
           on the other side."""
        self.cmd('ip link del', self.name, '|| true')
        self.node.delIntf(self)
        self.link = None


class FaucetLink(Link):
    """Link using FaucetIntfs"""

    def __init__(self, node1, node2, port1=None, port2=None,
                 intf_name1=None, intf_name2=None,
                 addr1=None, addr2=None, **params):
        Link.__init__(self, node1, node2, port1=port1, port2=port2,
                      intfName1=intf_name1, intfName2=intf_name2,
                      cls1=FaucetIntf, cls2=FaucetIntf,
                      addr1=addr1, addr2=addr2,
                      params1=params, params2=params)


class FaucetHost(CPULimitedHost):
    """Base Mininet Host class, for Mininet-based tests."""

    def __init__(self, *args, **kwargs):
        self.pid_files = []
        super().__init__(*args, **kwargs)

    def terminate(self):
        # If any 'dnsmasq' processes were started, terminate them now
        for pid_file in self.pid_files:
            with open(pid_file, 'r', encoding='utf-8') as pf:
                for _, pid in enumerate(pf):
                    os.kill(int(pid), 15)
        super().terminate()

    def create_dnsmasq(self, tmpdir, iprange, router, vlan, interface=None):
        """Start dnsmasq instance inside dnsmasq namespace"""
        if interface is None:
            interface = self.defaultIntf()
        dhcp_leasefile = os.path.join(tmpdir, f'nfv-dhcp-{self.name}-{iprange}-vlan{vlan}.leases')
        log_facility = os.path.join(tmpdir, f'nfv-dhcp-{self.name}-{iprange}-vlan{vlan}.log')
        pid_file = os.path.join(tmpdir, f'dnsmasq-{self.name}-{iprange}-vlan{vlan}.pid')
        self.pid_files.append(pid_file)
        cmd = 'dnsmasq'
        opts = ''
        opts += f' --dhcp-range={iprange},255.255.255.0'
        opts += ' --dhcp-sequential-ip'
        opts += f' --dhcp-option=option:router,{router}'
        opts += ' --no-resolv --txt-record=does.it.work,yes'
        opts += ' --bind-interfaces'
        opts += ' --except-interface=lo'
        opts += f' --interface={interface}'
        opts += f' --dhcp-leasefile={dhcp_leasefile}'
        opts += f' --log-facility={log_facility}'
        opts += f' --pid-file={pid_file}'
        opts += ' --conf-file='
        return self.cmd(cmd + opts)

    def run_dhclient(self, tmpdir, interface=None, timeout=10):
        """Run DHCLIENT to obtain ip address via DHCP"""
        if interface is None:
            interface = self.defaultIntf()
        cmd = 'dhclient'
        opts = ''
        opts += ' -1'
        opts += ' -d'
        opts += f' -pf {tmpdir}/dhclient-{self.name}.pid'
        opts += f' -lf {tmpdir}/dhclient-{self.name}.leases'
        opts += f' {interface}'
        dhclient_cmd = cmd + opts
        return self.cmd(mininet_test_util.timeout_cmd(dhclient_cmd, timeout), verbose=True)

    def return_ip(self):
        """Return host IP as a string"""
        return self.cmd('hostname -I')


class VLANHost(FaucetHost):
    """Implementation of a Mininet host on a tagged VLAN."""

    intf_root_name = None

    vlans = None
    vlan_intfs = None

    def config(self, vlans=None, **params):  # pylint: disable=arguments-differ
        """Configure VLANHost according to (optional) parameters:

        vlans (list): List of VLAN IDs (for the VLANs the host is configured to have)
            for default interface
        vlan_intfs (dict): Dictionary of interface IP addresses keyed by VLAN indices
        """
        super_config = super().config(**params)
        if vlans is None:
            vlans = [100]
        self.vlans = vlans
        self.vlan_intfs = {}
        cmds = []
        intf = self.defaultIntf()
        self.intf_root_name = intf.name
        if 'vlan_intfs' in params:
            vlan_intfs = params.get('vlan_intfs', {})
            for vlan_id, ip_addr in vlan_intfs.items():
                if isinstance(vlan_id, tuple):
                    # Interface will take multiply VLAN tagged packets
                    intf_name = f'{intf.name}'
                    for vlan_i in vlan_id:
                        prev_name = intf_name
                        # Cannot have intf name tu0xy-eth0.VID1.VID2 as that takes up too many bytes
                        intf_name += f'.{vlan_i}'
                        cmds.extend([
                            f'ip link add link {prev_name} name {intf_name} type vlan id {vlans[vlan_i]}',
                            f'ip link set dev {intf_name} up'
                        ])
                        self.nameToIntf[intf_name] = intf
                        self.vlan_intfs.setdefault(vlan_id, [])
                        self.vlan_intfs[vlan_id].append(intf_name)
                    cmds.append(f'ip -4 addr add {ip_addr} dev {intf_name}')
                else:
                    intf_name = f'{intf}.{vlans[vlan_id]}'
                    cmds.extend([
                        f'vconfig add {intf.name} {vlans[vlan_id]}',
                        f'ip -4 addr add {ip_addr} dev {intf_name}',
                        f'ip link set dev {intf_name} up'])
                    self.nameToIntf[intf_name] = intf
                    self.vlan_intfs[vlan_id] = intf_name
        else:
            vlan_intf_name = f'{intf}.{".".join(str(v) for v in vlans)}'
            cmds.extend([
                f'ip link set dev {vlan_intf_name} up',
                f'ip -4 addr add {params["ip"]} dev {vlan_intf_name}'])
            for vlan in vlans:
                cmds.append(f'vconfig add {intf} {vlan}')
            intf.name = vlan_intf_name
            self.nameToIntf[vlan_intf_name] = intf
        cmds.extend([
            f'ip -4 addr flush dev {intf}',
            f'ip -6 addr flush dev {intf}'])
        for cmd in cmds:
            self.cmd(cmd)
        return super_config


class FaucetSwitch(OVSSwitch):
    """Switch that will be used by all tests (netdev based OVS)."""

    clist = None

    controller_params = {
        'controller_burst_limit': 25,
        'controller_rate_limit': 100,
    }

    def __init__(self, name, **params):
        self.clist = []
        super().__init__(
            name=name, reconnectms=8000, **params)

    @staticmethod
    def _workaround(args):
        """Workarounds/hacks for errors resulting from
           cmd() calls within Mininet"""
        # Workaround: ignore ethtool errors on tap interfaces
        # This allows us to use tap tunnels as cables to switch ports,
        # for example to test against OvS in a VM.
        if (len(args) > 1 and args[0] == 'ethtool -K'
                and getattr(args[1], 'name', '').startswith('tap')):
            return True
        return False

    def cmd(self, *args, success=0, **kwargs):
        """Commands typically must succeed for proper switch operation,
           so we check the exit code of the last command in *args.
           success: desired exit code (or None to skip check)"""
        # pylint: disable=arguments-differ
        cmd_output = super().cmd(*args, **kwargs)
        exit_code = int(super().cmd('echo $?'))
        if success is not None and exit_code != success:
            msg = f"{args} exited with ({exit_code}):'{cmd_output}'"
            if self._workaround(args):
                warn('Ignoring:', msg, '\n')
            else:
                raise RuntimeError(msg)
        return cmd_output

    def attach(self, intf):
        "Attach an interface and set its port"
        super().attach(intf)
        # This should be done in Mininet, but we do it for now
        port = self.ports[intf]
        self.cmd('ovs-vsctl set Interface', intf, f'ofport_request={port}')

    def add_controller(self, controller):
        self.clist.append((
            self.name + controller.name,
            f'{controller.protocol}:{controller.IP()}:{controller.port}'))
        if self.listenPort:
            self.clist.append((self.name + '-listen',
                               f'ptcp:{self.listenPort}'))
        ccmd = '-- --id=@%s create Controller target=\\"%s\\"'
        if self.reconnectms:
            ccmd += f' max_backoff={self.reconnectms}'
        for param, value in self.controller_params.items():
            ccmd += f' {param}={value}'
        cargs = ' '.join(ccmd % (name, target)
                         for name, target in self.clist)
        # Controller ID list
        cids = ','.join('@%s' % name for name, _target in self.clist)
        # One ovs-vsctl command to rule them all!
        self.vsctl(cargs
                   + f' -- set bridge {self} controller=[{cids}]')

    def start(self, controllers):
        # Transcluded from Mininet source, since need to insert
        # controller parameters at switch creation time.
        int(self.dpid, 16)  # DPID must be a hex string
        switch_intfs = [intf for intf in self.intfList() if self.ports[intf] and not intf.IP()]
        # Command to add interfaces
        intfs = ' '.join(f' -- add-port {self} {intf}'
                         + self.intfOpts(intf)
                         for intf in switch_intfs)
        # Command to create controller entries
        self.clist = [(self.name + c.name, f'{c.protocol}:{c.IP()}:{c.port}')
                      for c in controllers]
        if self.listenPort:
            self.clist.append((self.name + '-listen',
                               f'ptcp:{self.listenPort}'))
        ccmd = '-- --id=@%s create Controller target=\\"%s\\"'
        if self.reconnectms:
            ccmd += f' max_backoff={self.reconnectms}'
        for param, value in self.controller_params.items():
            ccmd += f' {param}={value}'
        cargs = ' '.join(ccmd % (name, target)
                         for name, target in self.clist)
        # Controller ID list
        cids = ','.join('@%s' % name for name, _target in self.clist)
        # Try to delete any existing bridges with the same name
        if not self.isOldOVS():
            cargs += f' -- --if-exists del-br {self}'
        # One ovs-vsctl command to rule them all!
        self.vsctl(cargs
                   + f' -- add-br {self}'
                   + f' -- set bridge {self} controller=[{cids}]'
                   + self.bridgeOpts()
                   + intfs)
        # switch interfaces on mininet host, must have no IP config.
        for intf in switch_intfs:
            for ipv in (4, 6):
                self.cmd(f'ip -{ipv} addr flush dev {intf}')
            assert self.cmd(f'echo 1 > /proc/sys/net/ipv6/conf/{intf}/disable_ipv6') == ''
        # If necessary, restore TC config overwritten by OVS
        if not self.batch:
            for intf in self.intfList():
                self.TCReapply(intf)


class NoControllerFaucetSwitch(FaucetSwitch):
    """A switch without any controllers (typically for remapping hardware to software."""

    def start(self, _controllers):
        super().start(controllers=[])


class FaucetSwitchTopo(Topo):
    """FAUCET switch topology that contains a software switch."""

    CPUF = 0.5
    DELAY = '1ms'

    def __init__(self, *args, **kwargs):
        self.dpid_names = {}  # maps dpids to switch names
        self.switch_dpids = {}  # maps switch names to dpids
        self.switch_ports = {}  # maps switch names to port lists
        self.dpid_port_host = {}  # maps switch hosts to ports
        super().__init__(*args, **kwargs)

    @staticmethod
    def _get_sid_prefix(ports_served):
        """Return a unique switch/host prefix for a test."""
        # Linux tools require short interface names.
        id_chars = ''.join(sorted(string.ascii_letters + string.digits))  # pytype: disable=module-attr
        id_a = int(ports_served / len(id_chars))
        id_b = ports_served - (id_a * len(id_chars))
        return f'{id_chars[id_a]}{id_chars[id_b]}'

    def _add_tagged_host(self, sid_prefix, tagged_vids, host_n):
        """Add a single tagged test host."""
        host_name = 't%s%1.1u' % (sid_prefix, host_n + 1)
        return self.addHost(
            name=host_name, cls=VLANHost, vlans=tagged_vids, cpu=self.CPUF)

    def _add_untagged_host(self, sid_prefix, host_n, in_namespace=True):
        """Add a single untagged test host."""
        host_name = 'u%s%1.1u' % (sid_prefix, host_n + 1)
        return self.addHost(name=host_name, cls=FaucetHost, cpu=self.CPUF, inNamespace=in_namespace)

    def _add_extended_host(self, sid_prefix, host_n, e_cls, tmpdir):
        """Add a single extended test host."""
        host_name = 'e%s%1.1u' % (sid_prefix, host_n + 1)
        return self.addHost(name=host_name, cls=e_cls, host_n=host_n, tmpdir=tmpdir)

    def _add_faucet_switch(self, sid_prefix, dpid, hw_dpid, ovs_type):
        """Add a FAUCET switch."""
        switch_cls = FaucetSwitch
        switch_name = f's{sid_prefix}'
        self.switch_dpids[switch_name] = dpid
        self.dpid_names[dpid] = switch_name
        if hw_dpid and hw_dpid == dpid:
            remap_dpid = str(int(dpid) + 1)
            output('bridging hardware switch DPID %s (%x) dataplane via OVS DPID %s (%x)\n' % (
                dpid, int(dpid), remap_dpid, int(remap_dpid)))
            dpid = remap_dpid
            switch_cls = NoControllerFaucetSwitch
        return self.addSwitch(
            name=switch_name,
            cls=switch_cls,
            datapath=ovs_type,
            dpid=mininet_test_util.mininet_dpid(dpid))

    # Hardware switch port virtualization through
    # transparent OVS attachment bridge/patch panel
    #
    # Since FAUCET is talking to the hardware switch, it needs
    # to use the hardware switch's OpenFlow ports, rather than
    # the OpenFlow ports of the (transparent) OVS attachment bridge.

    def hw_remap_port(self, dpid, port):
        """Map OVS attachment bridge port number -> HW port number if necessary"""
        if dpid != self.hw_dpid:
            return port
        assert self.hw_ports
        return self.hw_ports[port - self.start_port]

    peer_link = namedtuple('peer_link', 'port peer_dpid peer_port')

    def hw_remap_peer_link(self, dpid, link):
        """Remap HW port numbers -> OVS port numbers in link if necessary"""
        port = self.hw_remap_port(dpid, link.port)
        peer_port = self.hw_remap_port(link.peer_dpid, link.peer_port)
        return self.peer_link(port, link.peer_dpid, peer_port)

    def dpid_ports(self, dpid):
        """Return port list for dpid, remapping if necessary"""
        name = self.dpid_names[dpid]
        ports = self.switch_ports[name]
        return [self.hw_remap_port(dpid, port) for port in ports]

    @staticmethod
    def extend_port_order(port_order=None, max_length=16):
        """Extend port_order to max_length if needed"""
        if not port_order:
            port_order = []
        return port_order + list(range(len(port_order), max_length + 1))

    def _add_links(self, switch, dpid, hosts, links_per_host):
        self.switch_ports.setdefault(switch, [])
        self.dpid_port_host.setdefault(int(dpid), {})
        index = 0
        for host in hosts:
            for _ in range(links_per_host):
                # Order of switch/host is important, since host may be in a container.
                port = self.start_port + self.port_order[index]
                self.addLink(switch, host, port1=port, delay=self.DELAY, use_htb=True)
                # Keep track of switch ports
                self.switch_ports.setdefault(switch, [])
                self.switch_ports[switch].append(port)
                self.dpid_port_host[int(dpid)][port] = host
                index += 1
        return index

    # pylint: disable=too-many-locals,arguments-differ
    def build(self, ovs_type, ports_sock, test_name, dpids,
              n_tagged=0, tagged_vid=100, n_untagged=0, links_per_host=0,
              n_extended=0, e_cls=None, tmpdir=None, hw_dpid=None, switch_map=None,
              host_namespace=None, start_port=SWITCH_START_PORT, port_order=None,
              get_serialno=mininet_test_util.get_serialno):
        if not host_namespace:
            host_namespace = {}
        self.hw_dpid = hw_dpid
        self.hw_ports = sorted(switch_map) if switch_map else []
        self.start_port = start_port
        maxlength = n_tagged + n_untagged + n_extended
        self.port_order = self.extend_port_order(
            port_order, maxlength)
        for dpid in dpids:
            serialno = get_serialno(ports_sock, test_name)
            sid_prefix = self._get_sid_prefix(serialno)
            tagged = [self._add_tagged_host(sid_prefix, [tagged_vid], host_n)
                      for host_n in range(n_tagged)]
            untagged = [self._add_untagged_host(
                sid_prefix, host_n, host_namespace.get(host_n, True))
                for host_n in range(n_untagged)]
            extended = [self._add_extended_host(sid_prefix, host_n, e_cls, tmpdir)
                        for host_n in range(n_extended)]
            switch = self._add_faucet_switch(sid_prefix, dpid, hw_dpid, ovs_type)
            self._add_links(switch, dpid, tagged + untagged + extended, links_per_host)


class BaseFAUCET(Controller):
    """Base class for FAUCET and Gauge controllers."""

    # Set to True to have cProfile output to controller log.
    CPROFILE = False
    controller_intf = None
    controller_ipv6 = False
    controller_ip = None
    pid_file = None
    tmpdir = None
    ofcap = None
    MAX_OF_PKTS = 5000
    MAX_CTL_TIME = 600

    BASE_CARGS = ' '.join((
        '--verbose',
        '--use-stderr',
        '--ryu-ofp-tcp-listen-port=%s'))

    RYU_CONF = """
[DEFAULT]
echo_request_interval=10
maximum_unreplied_echo_requests=5
socket_timeout=15
"""

    def __init__(self, name, tmpdir, controller_intf=None, controller_ipv6=False,
                 cargs='', **kwargs):
        name = f'{name}-{os.getpid()}'
        self.tmpdir = tmpdir
        self.controller_intf = controller_intf
        self.controller_ipv6 = controller_ipv6
        super().__init__(
            name, cargs=self._add_cargs(cargs, name), **kwargs)

    def _add_cargs(self, cargs, name):
        ofp_listen_host_arg = ''
        if self.controller_intf is not None:
            socket_type = socket.AF_INET
            if self.controller_ipv6:
                socket_type = socket.AF_INET6
            self.controller_ip = netifaces.ifaddresses(  # pylint: disable=c-extension-no-member
                self.controller_intf)[socket_type][0]['addr']
            ofp_listen_host_arg = f'--ryu-ofp-listen-host={self.controller_ip}'
        self.pid_file = os.path.join(self.tmpdir, name + '.pid')
        pid_file_arg = f'--ryu-pid-file={self.pid_file}'
        ryu_conf_file = os.path.join(self.tmpdir, 'ryu.conf')
        with open(ryu_conf_file, 'w', encoding='utf-8') as ryu_conf:
            ryu_conf.write(self.RYU_CONF)
        ryu_conf_arg = f'--ryu-config-file={ryu_conf_file}'
        return ' '.join((
            self.BASE_CARGS, pid_file_arg, ryu_conf_arg, ofp_listen_host_arg, cargs))

    def IP(self):  # pylint: disable=invalid-name,arguments-differ
        if self.controller_intf is not None:
            return self.controller_ip
        return super().IP()

    def _start_tcpdump(self):
        """Start a tcpdump for OF port."""
        self.ofcap = os.path.join(self.tmpdir, '-'.join((self.name, 'of.cap')))
        tcpdump_args = ' '.join((
            '-s 0',
            '-e',
            '-n',
            '-U',
            '-q',
            '-W 1',  # max files 1
            f'-G {self.MAX_CTL_TIME - 1}',
            f'-c {self.MAX_OF_PKTS}',
            f'-i {self.controller_intf}',
            f'-w {self.ofcap}',
            f'tcp and port {self.port}',
            '>/dev/null',
            '2>/dev/null',
        ))
        self.cmd(f'timeout {self.MAX_CTL_TIME} tcpdump {tcpdump_args} &')
        for _ in range(5):
            if os.path.exists(self.ofcap):
                return
            time.sleep(1)
        assert False, 'tcpdump of OF channel did not start'

    @staticmethod
    def _tls_cargs(ofctl_port, ctl_privkey, ctl_cert, ca_certs):
        """Add TLS/cert parameters to Ryu."""
        tls_cargs = []
        for carg_val, carg_key in ((ctl_privkey, 'ryu-ctl-privkey'),
                                   (ctl_cert, 'ryu-ctl-cert'),
                                   (ca_certs, 'ryu-ca-certs')):
            if carg_val:
                tls_cargs.append((f'--{carg_key}={carg_val}'))
        if tls_cargs:
            tls_cargs.append((f'--ryu-ofp-ssl-listen-port={ofctl_port}'))
        return ' '.join(tls_cargs)

    def _command(self, env, tmpdir, name, args):
        """Wrap controller startup command in shell script with environment."""
        env_vars = []
        for var, val in sorted(env.items()):
            env_vars.append('='.join((var, val)))
        script_wrapper_name = os.path.join(tmpdir, f'start-{name}.sh')
        cprofile_args = ''
        if self.CPROFILE:
            cprofile_args = 'python3 -m cProfile -s time'
        full_faucet_dir = os.path.abspath(mininet_test_util.FAUCET_DIR)
        with open(script_wrapper_name, 'w', encoding='utf-8') as script_wrapper:
            faucet_cli = (
                'PYTHONPATH=%s %s exec timeout %u %s %s %s $*\n' % (
                    os.path.dirname(full_faucet_dir),
                    ' '.join(env_vars),
                    self.MAX_CTL_TIME,
                    os.path.join(full_faucet_dir, '__main__.py'),
                    cprofile_args,
                    args))
            script_wrapper.write(faucet_cli)
        return f'/bin/sh {script_wrapper_name}'

    def ryu_pid(self):
        """Return PID of ryu-manager process."""
        if os.path.exists(self.pid_file) and os.path.getsize(self.pid_file) > 0:
            pid = None
            with open(self.pid_file, encoding='utf-8') as pid_file:
                pid = int(pid_file.read())
            return pid
        return None

    def listen_port(self, port, state='LISTEN'):
        """Return True if port in specified TCP state."""
        for ipv in (4, 6):
            listening_out = self.cmd(
                mininet_test_util.tcp_listening_cmd(port, ipv=ipv, state=state)).split()
            for pid in listening_out:
                if int(pid) == self.ryu_pid():
                    return True
        return False

    # pylint: disable=invalid-name
    @staticmethod
    def checkListening():
        """Mininet's checkListening() causes occasional false positives (with
           exceptions we can't catch), and we handle port conflicts ourselves anyway."""
        return

    def listening(self):
        """Return True if controller listening on required ports."""
        return self.listen_port(self.port)

    def connected(self):
        """Return True if at least one switch connected and controller healthy."""
        return self.healthy() and self.listen_port(self.port, state='ESTABLISHED')

    def logname(self):
        """Return log file for controller."""
        return os.path.join('/tmp', self.name + '.log')

    def healthy(self):
        """Return True if controller logging and listening on required ports."""
        if (os.path.exists(self.logname())
                and os.path.getsize(self.logname())
                and self.listening()):
            return True
        return False

    def start(self):
        """Start tcpdump for OF port and then start controller."""
        self._start_tcpdump()
        super().start()

    def _stop_cap(self):
        """Stop tcpdump for OF port and run tshark to decode it."""
        if os.path.exists(self.ofcap):
            self.cmd(' '.join(['fuser', '-15', '-k', self.ofcap]))
            text_ofcap_log = f'{self.ofcap}.txt'
            with open(text_ofcap_log, 'w', encoding='utf-8') as text_ofcap:
                subprocess.call(
                    ['timeout', str(self.MAX_CTL_TIME),
                     'tshark', '-l', '-n', '-Q',
                     '-d', f'tcp.port=={self.port},openflow',
                     '-O', 'openflow_v4',
                     '-Y', 'openflow_v4',
                     '-r', self.ofcap],
                    stdout=text_ofcap,
                    stdin=mininet_test_util.DEVNULL,
                    stderr=mininet_test_util.DEVNULL,
                    close_fds=True)

    def stop(self):  # pylint: disable=arguments-differ
        """Stop controller."""
        try:
            if self.CPROFILE:
                os.kill(self.ryu_pid(), 2)
            else:
                os.kill(self.ryu_pid(), 15)
        except (ProcessLookupError, TypeError):
            pass
        self._stop_cap()
        super().stop()
        if os.path.exists(self.logname()):
            tmpdir_logname = os.path.join(
                self.tmpdir, os.path.basename(self.logname()))
            if os.path.exists(tmpdir_logname):
                os.remove(tmpdir_logname)
            shutil.move(self.logname(), tmpdir_logname)


class FAUCET(BaseFAUCET):
    """Start a FAUCET controller."""

    START_ARGS = ['--ryu-app=ryu.app.ofctl_rest']

    def __init__(self, name, tmpdir, controller_intf, controller_ipv6, env,
                 ctl_privkey, ctl_cert, ca_certs,
                 ports_sock, prom_port, port, test_name, **kwargs):
        self.prom_port = prom_port
        self.ofctl_port = mininet_test_util.find_free_port(
            ports_sock, test_name)
        cargs = ' '.join((
            f'--ryu-wsapi-host={mininet_test_util.LOCALHOSTV6}',
            f'--ryu-wsapi-port={self.ofctl_port}',
            self._tls_cargs(port, ctl_privkey, ctl_cert, ca_certs)))
        super().__init__(
            name,
            tmpdir,
            controller_intf,
            controller_ipv6,
            cargs=cargs,
            command=self._command(env, tmpdir, name, ' '.join(self.START_ARGS)),
            port=port,
            **kwargs)

    def listening(self):
        return (
            self.listen_port(self.ofctl_port)
            and self.listen_port(self.prom_port)
            and super().listening())


class Gauge(BaseFAUCET):
    """Start a Gauge controller."""

    def __init__(self, name, tmpdir, controller_intf, controller_ipv6, env,
                 ctl_privkey, ctl_cert, ca_certs,
                 port, **kwargs):
        super().__init__(
            name,
            tmpdir,
            controller_intf, controller_ipv6,
            cargs=self._tls_cargs(port, ctl_privkey, ctl_cert, ca_certs),
            command=self._command(env, tmpdir, name, '--gauge'),
            port=port,
            **kwargs)
