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


def receive_sock_line(sock):
    buf = ''
    while buf.find('\n') <= -1:
        buf = buf + sock.recv(1024)
    return buf.strip()


def find_free_port(ports_socket, name):
    """Retrieve a free TCP port from test server."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(ports_socket)
    sock.sendall('GET,%s\n' % name)
    buf = receive_sock_line(sock)
    return [int(x) for x in buf.strip().split()]


def return_free_ports(ports_socket, name):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(ports_socket)
    sock.sendall('PUT,%s\n' % name)


def serve_ports(ports_socket):
    """Implement a TCP server to dispense free TCP ports."""
    ports_q = collections.deque()
    free_ports = set()

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
            if free_port in free_ports:
                continue
            break
        free_ports.add(free_port)
        return free_port

    def queue_free_ports():
        while len(ports_q) < 50:
            ports_q.append(get_port())
            time.sleep(0.1)

    queue_free_ports()
    ports_served = 0
    ports_by_name = collections.defaultdict(set)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(ports_socket)
    sock.listen(1)

    while True:
        connection, _ = sock.accept()
        command, name = receive_sock_line(connection).split(',')
        if command == 'PUT':
            for port in ports_by_name[name]:
                ports_q.append(port)
            del ports_by_name[name]
        else:
            if len(ports_q) == 0:
                queue_free_ports()
            port = ports_q.popleft()
            ports_served += 1
            ports_by_name[name].add(port)
            # pylint: disable=no-member
            connection.sendall('%u %u\n' % (port, ports_served))
        connection.close()


def timeout_cmd(cmd, timeout):
    return 'timeout -sKILL %us stdbuf -o0 -e0 %s' % (timeout, cmd)


def timeout_soft_cmd(cmd, timeout):
    return 'timeout %us stdbuf -o0 -e0 %s' % (timeout, cmd)
