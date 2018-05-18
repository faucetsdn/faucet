"""Helper class for working with tcpdump."""

import errno
import fcntl
import subprocess
import os
import re

import mininet_test_util
from mininet.log import error, debug


class TcpdumpHelper():

    pipe = None
    started = False
    last_line = None
    funcs = None
    readbuf = None
    blocking = True

    def __init__(self, tcpdump_host, tcpdump_filter, funcs=None,
            vflags='-v', timeout=10, packets=2, root_intf=False,
            pcap_out=None, intf_name=None, blocking=True):
        self.intf_name = intf_name if intf_name else tcpdump_host.intf().name
        self.funcs = funcs
        if root_intf:
            self.intf_name = self.intf_name.split('.')[0]

        tcpdump_flags=vflags
        tcpdump_flags+=' -c %u' % packets if packets else ''
        tcpdump_flags+=' -w %s' % pcap_out if pcap_out else ''
        tcpdump_cmd='tcpdump -i %s %s -e -n -U %s' % (self.intf_name, tcpdump_flags, tcpdump_filter)
        pipe_cmd=mininet_test_util.timeout_soft_cmd(tcpdump_cmd, timeout) if timeout else tcpdump_cmd

        debug(pipe_cmd)
        self.pipe = tcpdump_host.popen(
            pipe_cmd,
            stdin=mininet_test_util.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            close_fds=True)

        debug('tcpdump_helper stream fd %s %s' % (self.stream().fileno(), self.intf_name))

        self.readbuf = ''
        self.blocking(blocking)

    def stream(self):
        return self.pipe.stdout if self.pipe else None

    def blocking(self, blocking=True):
        fd = self.pipe.stdout.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        self.blocking = blocking
        if blocking:
            flags = flags & ~os.O_NONBLOCK
        else:
            flags = flags | os.O_NONBLOCK
        fcntl.fcntl(fd, fcntl.F_SETFL, flags)

    def execute(self):
        tcpdump_txt = ''
        # Initialize with meaningless truthy value.
        line = ' '
        while line:
            tcpdump_txt += line.strip()
            line = self.next_line()
            debug('tcpdump_helper fd %d line "%s"' % (self.stream().fileno(), line))
        return tcpdump_txt

    def terminate(self):
        if not self.pipe:
            return -1

        try:
            debug('tcpdump_helper terminate fd %s' % self.stream().fileno())
            self.pipe.kill()
            result = self.pipe.wait()
            if result == 124:
                # Mask valid result from timeout command.
                result = 0
            self.pipe.stdout.close()
            self.pipe = None
            return result
        except Exception as e:
            error('Error closing tcpdump_helper fd %d: %s' % (self.pipe.stdout.fileno(), e))
            return -2

    def readline(self):
        """Replacement readline() because built-in doesn't work with non-blocking IO"""
        fileno = self.pipe.stdout.fileno()
        while '\n' not in self.readbuf:
            try:
                read = os.read(fileno, 1024)
            except OSError as e:
                if e.errno != errno.EAGAIN or not self.blocking:
                    raise
                continue
            if len(read) == 0:
                line = self.readbuf
                self.readbuf = ''
                return line
            self.readbuf += read
        pos = self.readbuf.find('\n') + 1
        line = self.readbuf[0:pos]
        self.readbuf = self.readbuf[pos:]
        return line

    def next_line(self):
        while True:
            try:
                line = self.readline()
            except OSError as e:
                if e.errno == errno.EWOULDBLOCK or e.errno == errno.EAGAIN:
                    return None
                raise
            assert len(line) > 0 or self.started, 'tcpdump did not start: %s' % self.last_line.strip()
            if self.started:
                return line
            elif re.search('listening on %s' % self.intf_name, line):
                self.started = True
                # When we see tcpdump start, then call provided functions.
                if self.funcs is not None:
                    for func in self.funcs:
                        func()
            else:
                self.last_line = line
