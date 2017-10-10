"""Topology components for FAUCET Mininet unit tests."""

import os
import pty
import select
import socket
import string
import shutil
import subprocess
import time

import netifaces

# pylint: disable=import-error
from mininet.log import error, output
from mininet.topo import Topo
from mininet.node import Controller
from mininet.node import Host
from mininet.node import OVSSwitch

import faucet_mininet_test_util

# TODO: mininet 2.2.2 leaks ptys (master slave assigned in startShell)
# override as necessary close them. Transclude overridden methods
# to avoid multiple inheritance complexity.

class FaucetHostCleanup(object):
    """TODO: Mininet host implemenation leaks ptys."""

    master = None
    shell = None
    slave = None

    def startShell(self, mnopts=None):
        if self.shell:
            error('%s: shell is already running\n' % self.name)
            return
        opts = '-cd' if mnopts is None else mnopts
        if self.inNamespace:
            opts += 'n'
        cmd = ['mnexec', opts, 'env', 'PS1=' + chr(127),
               'bash', '--norc', '-is', 'mininet:' + self.name]
        self.master, self.slave = pty.openpty()
        self.shell = self._popen(
            cmd, stdin=self.slave, stdout=self.slave, stderr=self.slave,
            close_fds=False)
        self.stdin = os.fdopen(self.master, 'rw')
        self.stdout = self.stdin
        self.pid = self.shell.pid
        self.pollOut = select.poll()
        self.pollOut.register(self.stdout)
        self.outToNode[self.stdout.fileno()] = self
        self.inToNode[self.stdin.fileno()] = self
        self.execed = False
        self.lastCmd = None
        self.lastPid = None
        self.readbuf = ''
        while True:
            data = self.read(1024)
            if data[-1] == chr(127):
                break
            self.pollOut.poll()
        self.waiting = False
        self.cmd('unset HISTFILE; stty -echo; set +m')

    def terminate(self):
        if self.shell is not None:
            os.close(self.master)
            os.close(self.slave)
            self.shell.kill()
        self.cleanup()


class FaucetHost(FaucetHostCleanup, Host):

    pass


class FaucetSwitch(FaucetHostCleanup, OVSSwitch):
    """Switch that will be used by all tests (kernel based OVS)."""

    def __init__(self, name, **params):
        super(FaucetSwitch, self).__init__(
            name=name, datapath='kernel', **params)


class VLANHost(FaucetHost):
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
        # pylint: disable=no-member
        id_chars = string.letters + string.digits
        id_a = int(ports_served / len(id_chars))
        id_b = ports_served - (id_a * len(id_chars))
        return '%s%s' % (
            id_chars[id_a], id_chars[id_b])

    def _add_tagged_host(self, sid_prefix, tagged_vid, host_n):
        """Add a single tagged test host."""
        host_name = 't%s%1.1u' % (sid_prefix, host_n + 1)
        return self.addHost(name=host_name, cls=VLANHost, vlan=tagged_vid)

    def _add_untagged_host(self, sid_prefix, host_n):
        """Add a single untagged test host."""
        host_name = 'u%s%1.1u' % (sid_prefix, host_n + 1)
        return self.addHost(name=host_name, cls=FaucetHost)

    def _add_faucet_switch(self, sid_prefix, dpid):
        """Add a FAUCET switch."""
        switch_name = 's%s' % sid_prefix
        return self.addSwitch(
            name=switch_name,
            cls=FaucetSwitch,
            dpid=faucet_mininet_test_util.mininet_dpid(dpid))

    def build(self, ports_sock, test_name, dpids, n_tagged=0, tagged_vid=100, n_untagged=0):
        for dpid in dpids:
            serialno = faucet_mininet_test_util.get_serialno(
                ports_sock, test_name)
            sid_prefix = self._get_sid_prefix(serialno)
            for host_n in range(n_tagged):
                self._add_tagged_host(sid_prefix, tagged_vid, host_n)
            for host_n in range(n_untagged):
                self._add_untagged_host(sid_prefix, host_n)
            switch = self._add_faucet_switch(sid_prefix, dpid)
            for host in self.hosts():
                self.addLink(host, switch)


class FaucetHwSwitchTopo(FaucetSwitchTopo):
    """FAUCET switch topology that contains a hardware switch."""

    def build(self, ports_sock, test_name, dpids, n_tagged=0, tagged_vid=100, n_untagged=0):
        for dpid in dpids:
            serialno = faucet_mininet_test_util.get_serialno(
                ports_sock, test_name)
            sid_prefix = self._get_sid_prefix(serialno)
            for host_n in range(n_tagged):
                self._add_tagged_host(sid_prefix, tagged_vid, host_n)
            for host_n in range(n_untagged):
                self._add_untagged_host(sid_prefix, host_n)
            remap_dpid = str(int(dpid) + 1)
            output('bridging hardware switch DPID %s (%x) dataplane via OVS DPID %s (%x)' % (
                dpid, int(dpid), remap_dpid, int(remap_dpid)))
            dpid = remap_dpid
            switch = self._add_faucet_switch(sid_prefix, dpid)
            for host in self.hosts():
                self.addLink(host, switch)


class FaucetStringOfDPSwitchTopo(FaucetSwitchTopo):
    """String of datapaths each with hosts with a single FAUCET controller."""

    def build(self, ports_sock, test_name, dpids, n_tagged=0, tagged_vid=100, n_untagged=0):
        """

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
            serialno = faucet_mininet_test_util.get_serialno(
                ports_sock, test_name)
            sid_prefix = self._get_sid_prefix(serialno)
            hosts = []
            for host_n in range(n_tagged):
                hosts.append(self._add_tagged_host(sid_prefix, tagged_vid, host_n))
            for host_n in range(n_untagged):
                hosts.append(self._add_untagged_host(sid_prefix, host_n))
            switch = self._add_faucet_switch(sid_prefix, dpid)
            for host in hosts:
                self.addLink(host, switch)
            # Add a switch-to-switch link with the previous switch,
            # if this isn't the first switch in the topology.
            if last_switch is not None:
                self.addLink(last_switch, switch)
            last_switch = switch


class BaseFAUCET(Controller):
    """Base class for FAUCET and Gauge controllers."""

    # Set to True to have cProfile output to controller log.
    CPROFILE = False
    controller_intf = None
    controller_ip = None
    pid_file = None
    tmpdir = None
    ofcap = None

    BASE_CARGS = ' '.join((
        '--verbose',
        '--use-stderr',
        '--ofp-tcp-listen-port=%s'))

    def __init__(self, name, tmpdir, controller_intf=None, cargs='', **kwargs):
        name = '%s-%u' % (name, os.getpid())
        self.tmpdir = tmpdir
        self.controller_intf = controller_intf
        super(BaseFAUCET, self).__init__(
            name, cargs=self._add_cargs(cargs, name), **kwargs)

    def _add_cargs(self, cargs, name):
        ofp_listen_host_arg = ''
        if self.controller_intf is not None:
            # pylint: disable=no-member
            self.controller_ip = netifaces.ifaddresses(
                self.controller_intf)[socket.AF_INET][0]['addr']
            ofp_listen_host_arg = '--ofp-listen-host=%s' % self.controller_ip
        self.pid_file = os.path.join(self.tmpdir, name + '.pid')
        pid_file_arg = '--pid-file=%s' % self.pid_file
        return ' '.join((
            self.BASE_CARGS, pid_file_arg, ofp_listen_host_arg, cargs))

    def _start_tcpdump(self):
        """Start a tcpdump for OF port."""
        self.ofcap = os.path.join(self.tmpdir, '-'.join((self.name, 'of.cap')))
        tcpdump_args = ' '.join((
            '-s 0',
            '-e',
            '-n',
            '-U',
            '-q',
            '-i %s' % self.controller_intf,
            '-w %s' % self.ofcap,
            'tcp and port %u' % self.port,
            '>/dev/null',
            '2>/dev/null',
        ))
        self.cmd('tcpdump %s &' % tcpdump_args)

    def _tls_cargs(self, ofctl_port, ctl_privkey, ctl_cert, ca_certs):
        """Add TLS/cert parameters to Ryu."""
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
        """Wrap controller startup command in shell script with environment."""
        env_vars = []
        for var, val in list(sorted(env.items())):
            env_vars.append('='.join((var, val)))
        script_wrapper_name = os.path.join(tmpdir, 'start-%s.sh' % name)
        cprofile_args = ''
        if self.CPROFILE:
            cprofile_args = 'python3 -m cProfile -s time'
        with open(script_wrapper_name, 'w') as script_wrapper:
            script_wrapper.write(
                'PYTHONPATH=.:..:../faucet %s exec %s /usr/local/bin/ryu-manager %s $*\n' % (
                    ' '.join(env_vars), cprofile_args, args))
        return '/bin/sh %s' % script_wrapper_name

    def ryu_pid(self):
        """Return PID of ryu-manager process."""
        if os.path.exists(self.pid_file) and os.path.getsize(self.pid_file) > 0:
            pid = None
            with open(self.pid_file) as pid_file:
                pid = int(pid_file.read())
            return pid
        return None

    def listen_port(self, port, state='LISTEN'):
        """Return True if port in specified TCP state."""
        listening_out = self.cmd(
            faucet_mininet_test_util.tcp_listening_cmd(port, state=state)).split()
        for pid in listening_out:
            if int(pid) == self.ryu_pid():
                return True
        return False

    # pylint: disable=invalid-name
    def checkListening(self):
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
        if (os.path.exists(self.logname()) and
                os.path.getsize(self.logname()) and
                self.listening()):
            return True
        return False

    def start(self):
        """Start tcpdump for OF port and then start controller."""
        self._start_tcpdump()
        super(BaseFAUCET, self).start()

    def _stop_cap(self):
        """Stop tcpdump for OF port and run tshark to decode it."""
        if os.path.exists(self.ofcap):
            self.cmd(' '.join(['fuser', '-15', '-m', self.ofcap]))
            text_ofcap_log = '%s.txt' % self.ofcap
            with open(text_ofcap_log, 'w') as text_ofcap:
                subprocess.call(
                    ['tshark', '-l', '-n', '-Q',
                     '-d', 'tcp.port==%u,openflow' % self.port,
                     '-O', 'openflow_v4',
                     '-Y', 'openflow_v4',
                     '-r', self.ofcap],
                    stdout=text_ofcap,
                    stdin=faucet_mininet_test_util.DEVNULL,
                    stderr=faucet_mininet_test_util.DEVNULL,
                    close_fds=True)

    def stop(self):
        """Stop controller."""
        while self.healthy():
            if self.CPROFILE:
                os.kill(self.ryu_pid(), 2)
            else:
                os.kill(self.ryu_pid(), 15)
            time.sleep(1)
        self._stop_cap()
        super(BaseFAUCET, self).stop()
        if os.path.exists(self.logname()):
            tmpdir_logname = os.path.join(
                self.tmpdir, os.path.basename(self.logname()))
            if os.path.exists(tmpdir_logname):
                os.remove(tmpdir_logname)
            shutil.move(self.logname(), tmpdir_logname)


class FAUCET(BaseFAUCET):
    """Start a FAUCET controller."""

    def __init__(self, name, tmpdir, controller_intf, env,
                 ctl_privkey, ctl_cert, ca_certs,
                 ports_sock, port, test_name, **kwargs):
        self.ofctl_port = faucet_mininet_test_util.find_free_port(
            ports_sock, test_name)
        cargs = ' '.join((
            '--wsapi-host=%s' % faucet_mininet_test_util.LOCALHOST,
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

    def listening(self):
        return self.listen_port(self.ofctl_port) and super(FAUCET, self).listening()


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
