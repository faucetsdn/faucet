"""Helper class for working with tcpdump."""

import re
import subprocess

from mininet.log import error

import mininet_test_util
from mininet_test_base import pmonitor

class TcpdumpHelper():

    tcpdump_host = None
    tcpdump_out = None
    funcs = None

    def __init__(self, tcpdump_host, tcpdump_filter, funcs=None,
            vflags='-v', timeout=10, packets=2, root_intf=False):
        self.tcpdump_host = tcpdump_host
        self.funcs = funcs
        intf = tcpdump_host.intf().name
        if root_intf:
            intf = intf.split('.')[0]
        tcpdump_cmd = mininet_test_util.timeout_soft_cmd(
            'tcpdump -i %s -e -n -U %s -c %u %s' % (
                intf, vflags, packets, tcpdump_filter),
            timeout)
        self.tcpdump_out = tcpdump_host.popen(
            tcpdump_cmd,
            stdin=mininet_test_util.DEVNULL,
            stderr=subprocess.STDOUT,
            close_fds=True)

    def execute(self):
        popens = {self.tcpdump_host: self.tcpdump_out}
        tcpdump_started = False
        tcpdump_txt = ''
        for host, line in pmonitor(popens):
            if host == self.tcpdump_host:
                if tcpdump_started:
                    tcpdump_txt += line.strip()
                elif re.search('tcpdump: listening on ', line):
                    # when we see tcpdump start, then call provided functions.
                    tcpdump_started = True
                    if self.funcs is not None:
                        for func in self.funcs:
                            func()
                else:
                    error('tcpdump_helper: %s' % line)
        assert tcpdump_started, '%s did not start' % tcpdump_cmd
        return tcpdump_txt
