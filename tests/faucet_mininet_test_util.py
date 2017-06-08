#!/usr/bin/env python

"""Standalone utility functions for Mininet tests."""

import collections
import os
import socket
import time


FAUCET_DIR = os.getenv('FAUCET_DIR', '../faucet')
RESERVED_FOR_TESTS_PORTS = (179, 5001, 5002, 6633, 6653)


def mininet_dpid(int_dpid):
    """Return stringified hex version, of int DPID for mininet."""
    return str('%x' % int(int_dpid))


def str_int_dpid(str_dpid):
    """Return stringified int version, of int or hex DPID from YAML."""
    str_dpid = str(str_dpid)
    if str_dpid.startswith('0x'):
        return str(int(str_dpid, 16))
    else:
        return str(int(str_dpid))


def find_free_port(ports_socket):
    """Retrieve a free TCP port from test server."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(ports_socket)
    buf = ''
    while buf.find('\n') <= -1:
        buf = buf + sock.recv(1024)
    return [int(x) for x in buf.strip().split()]


def serve_ports(ports_socket):
    """Implement a TCP server to dispense free TCP ports."""
    ports_served = set()
    ports_q = collections.deque()

    def get_port():
        while True:
            free_socket = socket.socket()
            free_socket.bind(('', 0))
            free_port = free_socket.getsockname()[1]
            free_socket.close()
            if free_port < 1024:
                continue
            if free_port in RESERVED_FOR_TESTS_PORTS:
                continue
            if free_port in ports_served:
                continue
            break
        ports_served.add(free_port)
        return free_port

    def queue_free_ports():
        while len(ports_q) < 40:
            ports_q.append(get_port())
            time.sleep(0.1)

    queue_free_ports()

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(ports_socket)
    sock.listen(1)

    while True:
        queue_free_ports()
        free_port = ports_q.popleft()
        connection, _ = sock.accept()
        # pylint: disable=no-member
        connection.sendall('%u %u\n' % (free_port, len(ports_served)))
        connection.close()


def timeout_cmd(cmd, timeout):
    return 'timeout -sKILL %us stdbuf -o0 -e0 %s' % (timeout, cmd)


def timeout_soft_cmd(cmd, timeout):
    return 'timeout %us stdbuf -o0 -e0 %s' % (timeout, cmd)
